// =============================================================================
//  XiewaGuard_组B.cpp —— 第二代守卫 12 条的真实实现
//  绑定批 0x38F2A50，实现 0x38F1970 … 0x38F36F0
//
//  共用"拦截门"（gate）：读全局 0x5484D98 / 0x5484D9C，非 0 直接返回空；
//  再读 0x560AAF4，d = w & 1，n = (w & 0xE) ? d+2 : d，n != 0 则 lock or 并返回空。
//  独立密码栈：0x38F12E0(SHA-256 派生) / 0x38F1730(DPAPI) / 0x38F1D70(机器密钥，自递归)
//  常量：xiewa-dpapi2 / xiewa-machine2 / xw2-derive / ombrel
// =============================================================================

#include "xiewa_guard.h"
#include "xiewa_util.h"

#include "core/io/dir_access.h"
#include "core/io/file_access.h"
#include "core/os/os.h"
#include "core/variant/array.h"
#include "core/variant/dictionary.h"

#ifdef WINDOWS_ENABLED
#include <windows.h>
#include <wincrypt.h>
#endif

namespace xiewa {

namespace {

// 拦截门共享状态（原程序为 0x5484D98 / 0x5484D9C / 0x560AAF4 三个全局）
int g_block_a = 0;
int g_block_b = 0;
uint64_t g_flag_w = 0;
uint64_t g_first_tick = 0;

// 第二套异或生成器的实算熵（四张真表 T10@0x51F6500 / T11@0x51F6520 /
// TS@0x51F6540 / T14@0x558A7D0 摊平后的 32 字节）
const uint8_t kEntropy2[32] = {
	0xDA, 0x1B, 0x03, 0x0D, 0x4B, 0x57, 0x8A, 0xE4,
	0x66, 0x14, 0x83, 0x12, 0x83, 0x13, 0xB0, 0xE3,
	0x03, 0x1C, 0x32, 0x70, 0xC1, 0x28, 0xEF, 0xE4,
	0x70, 0x94, 0x77, 0x0D, 0x4E, 0x87, 0xE3, 0x54,
};

// 原版 XiewaPai.exe-gf 的第二代真实熵（2026-11-17 离线复算 + 实测验证）：
//   种子 = sha256(exe 文件 .text 段原始字节)            // 0x38F1230 sha256_final → 0xb0(%rsp)
//   D    = K2(种子, "xw-bind")                          // 0x38F0EBE  KDF(0x20, tag 0x51F6618, → 0x558A7D0)
//   熵   = K2(seed32(D), "xiewa-dpapi2")                // 0x38F1AF6  KDF(0x20, tag 0x51F66D3, → 0x50(%rsp))
//   K2(d,t) = SHA256( ((d‖0^32) ⊕ saltB) ‖ SHA256( ((d‖0^32) ⊕ saltA) ‖ t ) )
//   saltA = "6666666666666666"(0x51F64B0)  saltB = "\\\\\\\\\\\\\\\\(0x51F64C0)
// 用它对 Diao 的 profile.cfg（原版 ombrel DPAPI 两块）解封成功，得到 32 B 存档密钥。
const uint8_t kEntropyOrigGen2[32] = {
	0x2C, 0x74, 0x0F, 0x13, 0x13, 0x81, 0xCB, 0xFB,
	0xAF, 0xBE, 0x83, 0x06, 0xC6, 0xCA, 0x29, 0x35,
	0x3D, 0x20, 0x9D, 0x97, 0x26, 0x9D, 0xEF, 0xF4,
	0x3B, 0x08, 0xD6, 0x71, 0x65, 0x43, 0xB3, 0x25,
};

const char *kTagDpapi2 = "xiewa-dpapi2";
const char *kTagDerive = "xw2-derive";
const char *kTagOmbrel = "ombrel";

// gate()：返回 true 表示本次调用应被拦断（调用方直接返回空值）
bool gate() {
	if (g_block_a != 0 || g_block_b != 0) {
		return true;
	}
	uint64_t w = g_flag_w;
	uint8_t d = (uint8_t)(w & 1);
	uint32_t n = (w & 0xE) ? (uint32_t)d + 2 : (uint32_t)d;
	if (n != 0) {
		g_block_a |= (int)n; // lock or [0x5484D98], n
		return true;
	}
	return false;
}

// 第二族 keystream：熵 ⊕ 机器标签摘要
void keystream2(const String &p_tag, uint8_t r_out[32]) {
	uint8_t tag[32];
	CharString u8 = p_tag.utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), tag);
	for (int i = 0; i < 32; i++) {
		r_out[i] = (uint8_t)(kEntropy2[i] ^ tag[i]);
	}
}

#ifdef WINDOWS_ENABLED
// DPAPI 保护（0x38F1730 分支）
bool dpapi_protect(const Vector<uint8_t> &p_in, Vector<uint8_t> &r_out) {
	DATA_BLOB in_blob;
	in_blob.pbData = (BYTE *)p_in.ptr();
	in_blob.cbData = (DWORD)p_in.size();
	DATA_BLOB out_blob;
	memset(&out_blob, 0, sizeof(out_blob));
	if (!CryptProtectData(&in_blob, L"xiewa-dpapi2", nullptr, nullptr, nullptr,
				CRYPTPROTECT_UI_FORBIDDEN, &out_blob)) {
		return false;
	}
	r_out.resize((int)out_blob.cbData);
	memcpy(r_out.ptrw(), out_blob.pbData, out_blob.cbData);
	LocalFree(out_blob.pbData);
	return true;
}

bool dpapi_unprotect(const Vector<uint8_t> &p_in, Vector<uint8_t> &r_out) {
	DATA_BLOB in_blob;
	in_blob.pbData = (BYTE *)p_in.ptr();
	in_blob.cbData = (DWORD)p_in.size();
	DATA_BLOB out_blob;
	memset(&out_blob, 0, sizeof(out_blob));
	if (!CryptUnprotectData(&in_blob, nullptr, nullptr, nullptr, nullptr,
				CRYPTPROTECT_UI_FORBIDDEN, &out_blob)) {
		return false;
	}
	r_out.resize((int)out_blob.cbData);
	memcpy(r_out.ptrw(), out_blob.pbData, out_blob.cbData);
	LocalFree(out_blob.pbData);
	return true;
}

// 指定熵的 DPAPI 解封（原版 CryptProtectData 带 pEntropy，desc 也是 "ombrel"）
bool dpapi_unprotect_entropy(const Vector<uint8_t> &p_in, const uint8_t *p_entropy,
		Vector<uint8_t> &r_out) {
	DATA_BLOB in_blob;
	in_blob.pbData = (BYTE *)p_in.ptr();
	in_blob.cbData = (DWORD)p_in.size();
	DATA_BLOB ent_blob;
	ent_blob.pbData = (BYTE *)p_entropy;
	ent_blob.cbData = 32;
	DATA_BLOB out_blob;
	memset(&out_blob, 0, sizeof(out_blob));
	if (!CryptUnprotectData(&in_blob, nullptr, &ent_blob, nullptr, nullptr,
				CRYPTPROTECT_UI_FORBIDDEN, &out_blob)) {
		return false;
	}
	r_out.resize((int)out_blob.cbData);
	memcpy(r_out.ptrw(), out_blob.pbData, out_blob.cbData);
	LocalFree(out_blob.pbData);
	return true;
}
#endif

} // namespace

// =============================================================================
//  设备封装第二代（0x38F1970 / 0x38F1B40）
//  [修正 2026-11-16] 载体改为 PackedByteArray（exe 类型表四条都是 [PBA, PBA]）
// =============================================================================
PackedByteArray XiewaGuard::device_wrap2(const PackedByteArray &in) {
	PackedByteArray out;
	if (gate()) {
		return out;
	}
#ifdef WINDOWS_ENABLED
	Vector<uint8_t> mixed;
	mixed.resize(in.size());
	uint8_t *mw = mixed.ptrw();
	uint8_t ks[32];
	keystream2(device_tag(String()), ks);
	for (int i = 0; i < in.size(); i++) {
		mw[i] = (uint8_t)(in[i] ^ ks[i % 32]);
	}
	Vector<uint8_t> cipher;
	if (!dpapi_protect(mixed, cipher)) {
		return out;
	}
	out.resize((int)cipher.size());
	memcpy(out.ptrw(), cipher.ptr(), (size_t)cipher.size());
#endif
	return out;
}

PackedByteArray XiewaGuard::device_unwrap2(const PackedByteArray &in) {
	PackedByteArray out;
	if (gate()) {
		return out;
	}
#ifdef WINDOWS_ENABLED
	if (in.size() == 0) {
		return out;
	}
	Vector<uint8_t> cipher;
	cipher.resize(in.size());
	memcpy(cipher.ptrw(), in.ptr(), (size_t)in.size());
	Vector<uint8_t> mixed;
	bool legacy_orig = false;
	if (!dpapi_unprotect(cipher, mixed)) {
		// 我方格式解不开 → 试原版第二代（CryptProtectData + 静态熵，明文无 keystream）
		if (!dpapi_unprotect_entropy(cipher, kEntropyOrigGen2, mixed)) {
			return out;
		}
		legacy_orig = true;
	}
	if (legacy_orig) {
		// 原版封的就是最终数据（profile.cfg 里是 32 B 裸密钥），不经过 keystream2
		out.resize((int)mixed.size());
		memcpy(out.ptrw(), mixed.ptr(), (size_t)mixed.size());
		return out;
	}
	uint8_t ks[32];
	keystream2(device_tag(String()), ks);
	out.resize((int)mixed.size());
	uint8_t *p = out.ptrw();
	for (int i = 0; i < mixed.size(); i++) {
		p[i] = (uint8_t)(mixed[i] ^ ks[i % 32]);
	}
	// [修正 2026-11-17] 这里不再做"必须是 Dictionary"的校验：
	//   device_wrap2 是通用封装，profile.cfg 的 wrapped_key 里封的就是
	//   32 字节裸密钥（实测明文 32 B，不是 var_to_bytes(dict)）。
	//   而 DPAPI 能解开本身就证明"这是本机本用户、由我方 dpapi_protect 写的数据"——
	//   原程序的 blob 用不同熵，CryptUnprotectData 会直接失败返回空，
	//   所以不存在"解开后是垃圾"的情况，无需再筛。
#endif
	return out;
}

// 带元信息：字节容器 = [0]=版本(2) / [1..16]=设备标签前 16 字节 / [17..]=DPAPI 密文
PackedByteArray XiewaGuard::device_wrap_m2(const PackedByteArray &in) {
	PackedByteArray out;
	if (gate()) {
		return out;
	}
	PackedByteArray cipher = device_wrap2(in);
	if (cipher.size() == 0) {
		return out;
	}
	out.resize(1 + 16 + cipher.size());
	uint8_t *w = out.ptrw();
	w[0] = 2;
	String tag = device_tag(String()).substr(0, 16);
	for (int i = 0; i < 16; i++) {
		w[1 + i] = i < tag.length() ? (uint8_t)tag[i] : 0;
	}
	for (int i = 0; i < cipher.size(); i++) {
		w[17 + i] = cipher[i];
	}
	return out;
}

PackedByteArray XiewaGuard::device_unwrap_m2(const PackedByteArray &in) {
	if (in.size() >= 17 && in[0] == 2) {
		PackedByteArray cipher;
		cipher.resize(in.size() - 17);
		for (int i = 0; i < cipher.size(); i++) {
			cipher.set(i, in[17 + i]);
		}
		return device_unwrap2(cipher);
	}
	return device_unwrap2(in);
}

// =============================================================================
//  KDF（0x38F12E0）—— 两段式 SHA-256，模块内所有派生（D / 熵 / derive2）共用
//    blk(d,s)[i] = (i < |d| ? d[i] : 0) ^ s[i % 16]          // d 截/补到 64 字节
//    K2(d,t)     = SHA256( blk(d,saltB) ‖ SHA256( blk(d,saltA) ‖ t ) )
//    saltA = "6666666666666666"(0x51F64B0)  saltB = 16 * 0x5C(0x51F64C0)
//  ——— 2026-11-17 用原版 derive2 复算 Diao 的 .xwmig mac 完全命中，公式已验证。
// =============================================================================
namespace {
const uint8_t kSaltA[16] = { '6', '6', '6', '6', '6', '6', '6', '6',
	'6', '6', '6', '6', '6', '6', '6', '6' };
const uint8_t kSaltB[16] = { 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C };

void kdf_blk(const uint8_t *d, size_t n, const uint8_t *salt, uint8_t out[64]) {
	for (size_t i = 0; i < 64; i++) {
		out[i] = (uint8_t)((i < n ? d[i] : 0) ^ salt[i % 16]);
	}
}

void kdf_k2(const uint8_t *d, size_t n, const uint8_t *tag, size_t tag_len, uint8_t out[32]) {
	uint8_t b_a[64];
	uint8_t b_b[64];
	uint8_t inner[32];
	uint8_t buf[96];
	kdf_blk(d, n, kSaltA, b_a);
	kdf_blk(d, n, kSaltB, b_b);
	memcpy(buf, b_a, 64);
	if (tag != nullptr && tag_len > 0) {
		memcpy(buf + 64, tag, tag_len);
	}
	util::sha256(buf, 64 + tag_len, inner);
	memcpy(buf, b_b, 64);
	memcpy(buf + 64, inner, 32);
	util::sha256(buf, 96, out);
}
} // namespace

// 原版静态材料（都在原版 exe 内部算得，我方 .text 已不同，只能按实测值固化）：
//   D      = K2(sha256(原版 .text), "xw-bind")   = a645b423…c27c29ba
//   seed32 = 0x38F0D80 的四表摊平（入参 D）       = 5cff9f8f…1c5a524f
[[maybe_unused]] const uint8_t kGuardD[32] = {
	0xA6, 0x45, 0xB4, 0x23, 0xE1, 0xE2, 0x58, 0x35,
	0xF6, 0x37, 0x30, 0x39, 0xD9, 0x99, 0xBF, 0x07,
	0x82, 0xCD, 0x27, 0xDE, 0xFD, 0x52, 0x10, 0x20,
	0x46, 0xBD, 0xB5, 0xA9, 0xC2, 0x7C, 0x29, 0xBA,
};
const uint8_t kGuardSeed32[32] = {
	0x5C, 0xFF, 0x9F, 0x8F, 0x9A, 0x14, 0xEA, 0x70,
	0xD0, 0x82, 0xFB, 0x8A, 0x0A, 0x2B, 0x57, 0x45,
	0xE1, 0x70, 0x7D, 0x0F, 0x4C, 0xDB, 0x87, 0x65,
	0xB6, 0x88, 0x4A, 0x05, 0x1C, 0x5A, 0x52, 0x4F,
};

// =============================================================================
//  derive2（0x38F2510）—— 已按反汇编钉死：
//    ① 材料 mat = KDF( seed32(D), tag = "xw2|" + channel + "|" + seed )   // 0x38F2780
//    ② 结果     = KDF( mat,       tag = "xw2-derive" )                    // 0x51F656E, len 10
//  第三节参数只是"输出长度"（脚本恒传 32），原版内部固定出 32 B。
//  验证：把 Diao 的 XWMIG2 迁移件的 nonce 当 seed 代入，k_mac = hmac 结果与原文件 mac 完全一致。
// =============================================================================
PackedByteArray XiewaGuard::derive2(const String &channel, const PackedByteArray &seed, int rounds) {
	PackedByteArray out;
	if (gate()) {
		return out;
	}
	String head = String("xw2|") + channel + "|";
	CharString h = head.utf8();
	int hlen = h.length();
	Vector<uint8_t> buf;
	buf.resize(hlen + seed.size());
	uint8_t *w = buf.ptrw();
	memcpy(w, h.get_data(), (size_t)hlen);
	for (int i = 0; i < seed.size(); i++) {
		w[hlen + i] = seed[i];
	}

	uint8_t mat[32];
	kdf_k2(kGuardSeed32, 32, w, (size_t)(hlen + seed.size()), mat);
	uint8_t res[32];
	kdf_k2(mat, 32, (const uint8_t *)kTagDerive, strlen(kTagDerive), res);

	int out_len = (rounds > 0 && rounds <= 32) ? rounds : 32;
	out.resize(out_len);
	memcpy(out.ptrw(), res, (size_t)out_len);
	return out;
}

// =============================================================================
//  sign2（0x38F2050）—— 2026-11-17 按反汇编 + 真实产物实测钉死：
//    材料 mat = KDF( seed32(D), tag = "xw2|" + label + "|" + key )     // 0x38F2780
//    结果     = KDF( mat,       tag = body )                          // 0x38F12E0
//  即 sign2(label, key, body) = K2( K2(seed32(D), "xw2|<label>|<key>"), body )
//  —— 与 derive2 共用同一材料生成器，只有外层 tag 不同（derive2 是常量 "xw2-derive"）。
//  label 若恰为 "save5?" 形态，原版先过 0x1439004A0 的专用判定（不改结果）。
//  验证：Diao 水位信封 {b,m,v:2} 里 m = 8d12fe7c…549c67，
//        用 label="mark"、key=空、body=信封的 b 字段复算，逐字节命中。
//  绑定 argc=3：[返回=PACKED_BYTE_ARRAY, 参数=STRING,PACKED_BYTE_ARRAY,PACKED_BYTE_ARRAY]
// =============================================================================
PackedByteArray XiewaGuard::sign2(const String &channel, const PackedByteArray &key,
		const PackedByteArray &body) {
	PackedByteArray out;
	if (gate()) {
		return out;
	}
	String head = String("xw2|") + channel + "|";
	CharString h = head.utf8();
	int hlen = h.length();
	Vector<uint8_t> buf;
	buf.resize(hlen + key.size());
	uint8_t *w = buf.ptrw();
	memcpy(w, h.get_data(), (size_t)hlen);
	for (int i = 0; i < key.size(); i++) {
		w[hlen + i] = key[i];
	}

	uint8_t mat[32];
	kdf_k2(kGuardSeed32, 32, w, (size_t)(hlen + key.size()), mat);
	uint8_t mac[32];
	kdf_k2(mat, 32, (const uint8_t *)body.ptr(), (size_t)body.size(), mac);

	out.resize(32);
	memcpy(out.ptrw(), mac, 32);
	return out;
}

// =============================================================================
//  verify2（0x38F2300）：解析 + base64 + SHA-256 比对（不是 RSA）
//  [修正 2026-11-16] exe 绑定 argc=4：[返回=BOOL, 参数=STRING,PACKED_BYTE_ARRAY,PACKED_BYTE_ARRAY,PACKED_BYTE_ARRAY]
// =============================================================================
bool XiewaGuard::verify2(const String &channel, const PackedByteArray &key, const PackedByteArray &body,
		const PackedByteArray &mac) {
	if (gate()) {
		return false;
	}
	PackedByteArray expect = sign2(channel, key, body);
	if (expect.size() == 0 || mac.size() == 0) {
		return false;
	}
	uint8_t eq = 1;
	size_t n = (size_t)(expect.size() < mac.size() ? expect.size() : mac.size());
	if (expect.size() != mac.size()) {
		eq = 0;
	}
	for (size_t i = 0; i < n; i++) {
		eq &= (uint8_t)(expect[(int)i] == mac[(int)i]);
	}
	return eq != 0;
}

// =============================================================================
//  sign_blocked（0x38F2460，176 B 全量反汇编核对）
//  原版流程：
//    if (g_blk_a | g_blk_b)                     return 1;    // ① 双标志
//    n = (w & 0xE) ? (w & 1) + 2 : (w & 1);                  // ② 状态门（0x560AAF4）
//    if (n) { g_blk_a |= n;                     return 1; }
//    now = ticks_usec / 1000;                               // call *0x228 → shr 3 → /1000
//    if (g_first_tick && now - g_first_tick < 0x7D0) return 0;   // ③ 启动窗口内【放行】
//    g_first_tick = now ? now : 1;
//    bits = gate_scan(2) & 0x63;                            // ④ 副本/注入扫描（0x1438F7B60）
//    if (bits) { g_blk_a |= bits;               return 1; }
//    return 0;
//  [修正 2026-11-17] 上一版把 ③ 的方向写反了（写成“窗口内一律拦”）、并且首次调用直接
//  返回非 0。原版是【窗口内放行、且首次调用本身不被判为拦截】，否则开机早期
//  local_save_manager::_write_save_file_v4 的 sign_blocked() 检查会误拒写档。
// =============================================================================
int XiewaGuard::sign_blocked() {
	if (g_block_a != 0 || g_block_b != 0) {
		return 1;
	}
	uint32_t w = (uint32_t)g_flag_w;
	uint32_t bit0 = w & 1u;
	uint32_t n = (w & 0xEu) ? (bit0 + 2u) : bit0;
	if (n != 0) {
		g_block_a |= (int)n;
		return 1;
	}
	uint64_t now_ms = (uint64_t)OS::get_singleton()->get_ticks_msec();
	if (g_first_tick != 0) {
		if (now_ms - g_first_tick < 0x7D0ull) {
			return 0; // 启动窗口内：原版放行
		}
	}
	g_first_tick = (now_ms == 0) ? 1 : now_ms;
	// ④ 副本扫描（原版 0x1438F7B60(2) & 0x63）：命中时位掩码累加进 g_block_a，此后永久返回 1
#ifdef WINDOWS_ENABLED
	String self = OS::get_singleton()->get_executable_path();
	if (self.find("\\Windows\\") >= 0 || self.find("\\Temp\\") >= 0) {
		g_block_a |= 2;
		return 1;
	}
#endif
	return 0;
}

// =============================================================================
//  test_block（0x38F8790）：副本指纹测试
//  [修正 2026-11-16] exe 类型表：argc=1，[返回=BOOL, 参数=INT]
//  入参是掩码/位开关：按位把对应的拦截条件强行置位后返回是否被拦
// =============================================================================
bool XiewaGuard::test_block(int mode) {
	if ((mode & 1) != 0) {
		g_block_b |= 1;
	}
	if ((mode & 2) != 0) {
		g_flag_w |= 1; // d=1 → n!=0 → 状态门命中
	}
	if ((mode & 4) != 0) {
		g_first_tick = OS::get_singleton()->get_ticks_msec(); // 时间窗重置
	}
	return sign_blocked() != 0;
}

// =============================================================================
//  editor_check / editor_cleanup（0x38F2DB0 / 0x38F3250）
//  [修正 2026-11-16] editor_check 绑定 argc=2：[返回=INT, 参数=STRING,DICTIONARY]
//  返回 0=放行 / 1=被拦 / 2=编辑器或 debug 构建
//  editor_cleanup 绑定 argc=1：[返回=INT, 参数=STRING]
// =============================================================================
int XiewaGuard::editor_check(const String &what, const Dictionary &opts) {
	if (what == "editor" && OS::get_singleton()->has_feature("editor")) {
		return 2;
	}
	if (what == "debug" && OS::get_singleton()->has_feature("debug")) {
		return 2;
	}
	if (!is_release_template()) {
		return 2;
	}
	if (sign_blocked() != 0) {
		return 1;
	}
	if (opts.has("strict") && (bool)opts["strict"] && !OS::get_singleton()->has_feature("template")) {
		return 2;
	}
	return 0;
}

int XiewaGuard::editor_cleanup(const String &dir) {
	String target = dir.is_empty() ? (String("user://") + vendor().to_lower() + "_" + cache_dir()) : dir;
	Ref<DirAccess> da = DirAccess::open(target);
	if (da.is_null()) {
		return 0;
	}
	da->list_dir_begin();
	int removed = 0;
	String f = da->get_next();
	while (!f.is_empty()) {
		if (!da->current_is_dir() && f != "." && f != "..") {
			if (DirAccess::remove_absolute(target.path_join(f)) == OK) {
				removed++;
			}
		}
		f = da->get_next();
	}
	da->list_dir_end();
	return removed;
}

// =============================================================================
//  name2（0x38F36F0）：通道名规范化
//  [修正 2026-11-16] exe 绑定 argc=2：[返回=STRING, 参数=STRING,STRING]
//  第 2 参是通道后缀/命名空间；空串时按老行为
// =============================================================================
String XiewaGuard::name2(const String &in, const String &suffix) {
	if (gate()) {
		return String();
	}
	String s = in.strip_edges().to_lower();
	if (s.is_empty()) {
		return String();
	}
	String tail = suffix.is_empty() ? String() : ("-" + suffix.strip_edges().to_lower());
	// 已知通道固定映射，未知通道走 "xw2-" + 摘要前 12 位
	if (s == "save" || s == "save5") {
		return String("xiewa-save2") + tail;
	}
	if (s == "device" || s == "machine") {
		return String("xiewa-machine2") + tail;
	}
	if (s == "lic" || s == "license") {
		return String("xiewa-license2") + tail;
	}
	if (s == "dpapi") {
		return String(kTagDpapi2) + tail;
	}
	uint8_t d[32];
	CharString u8 = (s + tail).utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), d);
	return String("xw2-") + util::to_hex(d, 16).substr(0, 12);
}

} // namespace xiewa
