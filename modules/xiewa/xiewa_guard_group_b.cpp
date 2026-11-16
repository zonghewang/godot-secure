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
	if (!dpapi_unprotect(cipher, mixed)) {
		return out;
	}
	uint8_t ks[32];
	keystream2(device_tag(String()), ks);
	out.resize((int)mixed.size());
	uint8_t *p = out.ptrw();
	for (int i = 0; i < mixed.size(); i++) {
		p[i] = (uint8_t)(mixed[i] ^ ks[i % 32]);
	}
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
//  derive2（0x38F2510）：三段 SHA-256 派生，标签 xw2-derive
//  [修正 2026-11-16] exe 绑定 argc=3：[返回=PACKED_BYTE_ARRAY, 参数=STRING,PACKED_BYTE_ARRAY,INT]
// =============================================================================
PackedByteArray XiewaGuard::derive2(const String &channel, const PackedByteArray &seed, int rounds) {
	PackedByteArray out;
	if (gate()) {
		return out;
	}
	if (rounds < 1) {
		rounds = 3; // 原程序默认段数 3（argc 给了就用给的）
	}
	if (rounds > 64) {
		rounds = 64;
	}
	// 种子材料 = channel|seed|ombrel
	Vector<uint8_t> buf;
	buf.resize(0);
	String prefix = channel + "|" + String(kTagDerive) + "|";
	CharString pre = prefix.utf8();
	buf.resize(pre.length() + seed.size() + (int)strlen(kTagOmbrel) + 1);
	uint8_t *w = buf.ptrw();
	memcpy(w, pre.get_data(), (size_t)pre.length());
	int off = pre.length();
	for (int i = 0; i < seed.size(); i++) {
		w[off + i] = seed[i];
	}
	off += seed.size();
	memcpy(w + off, kTagOmbrel, strlen(kTagOmbrel));
	off += (int)strlen(kTagOmbrel);

	uint8_t cur[32];
	util::sha256(w, (size_t)off, cur);
	for (int round = 0; round < rounds; round++) {
		uint8_t next[32];
		util::sha256(cur, 32, next);
		memcpy(cur, next, 32);
	}
	out.resize(32);
	memcpy(out.ptrw(), cur, 32);
	return out;
}

// =============================================================================
//  sign2（0x38F2050）：HMAC + "save5…" 标签判定 + 时间窗
//  [修正 2026-11-16] exe 绑定 argc=3：[返回=PACKED_BYTE_ARRAY, 参数=STRING,PACKED_BYTE_ARRAY,PACKED_BYTE_ARRAY]
// =============================================================================
PackedByteArray XiewaGuard::sign2(const String &channel, const PackedByteArray &data,
		const PackedByteArray &key) {
	PackedByteArray out;
	if (gate()) {
		return out;
	}
	// HMAC 密钥 = pepper 原始 32 字节 ‖ 脚本给的密钥 ‖ 通道标签
	PackedByteArray pep = pepper();
	Vector<uint8_t> kb;
	kb.resize(pep.size() + key.size() + 16);
	uint8_t *kw = kb.ptrw();
	memcpy(kw, pep.ptr(), (size_t)pep.size());
	int off = pep.size();
	for (int i = 0; i < key.size(); i++) {
		kw[off + i] = key[i];
	}
	off += key.size();
	String tail = "|" + channel;
	CharString t8 = tail.utf8();
	memcpy(kw + off, t8.get_data(), (size_t)t8.length());
	off += t8.length();

	// 待签材料：存档类前缀 save5 时追加 "|save"（与原程序标签判定一致）
	Vector<uint8_t> mb;
	mb.resize(data.size() + 6);
	uint8_t *mw = mb.ptrw();
	for (int i = 0; i < data.size(); i++) {
		mw[i] = data[i];
	}
	int mlen = data.size();
	bool is_save = false;
	if (data.size() >= 5) {
		const char *p = (const char *)data.ptr();
		is_save = (p[0] == 's' && p[1] == 'a' && p[2] == 'v' && p[3] == 'e' && p[4] == '5');
	}
	if (is_save) {
		memcpy(mw + mlen, "|save", 5);
		mlen += 5;
	}

	uint8_t mac[32];
	util::hmac_sha256(kw, (size_t)off, mw, (size_t)mlen, mac);
	out.resize(32);
	memcpy(out.ptrw(), mac, 32);
	return out;
}

// =============================================================================
//  verify2（0x38F2300）：解析 + base64 + SHA-256 比对（不是 RSA）
//  [修正 2026-11-16] exe 绑定 argc=4：[返回=BOOL, 参数=STRING,PACKED_BYTE_ARRAY,PACKED_BYTE_ARRAY,PACKED_BYTE_ARRAY]
// =============================================================================
bool XiewaGuard::verify2(const String &channel, const PackedByteArray &data, const PackedByteArray &sig,
		const PackedByteArray &key) {
	if (gate()) {
		return false;
	}
	PackedByteArray expect = sign2(channel, data, key);
	if (expect.size() == 0 || sig.size() == 0) {
		return false;
	}
	uint8_t eq = 1;
	size_t n = (size_t)(expect.size() < sig.size() ? expect.size() : sig.size());
	if (expect.size() != sig.size()) {
		eq = 0;
	}
	for (size_t i = 0; i < n; i++) {
		eq &= (uint8_t)(expect[(int)i] == sig[(int)i]);
	}
	return eq != 0;
}

// =============================================================================
//  sign_blocked（0x38F2460）：三块 —— 双标志 / 状态门 / 时间窗 + 副本扫描
//  [修正 2026-11-16] exe 类型表：[返回=INT] → 掩码 1/2/4/8，非 0 即被拦
// =============================================================================
int XiewaGuard::sign_blocked() {
	int mask = 0;
	// ① 双标志
	if (g_block_a != 0 || g_block_b != 0) {
		mask |= 1;
	}
	// ② 状态门（0x560AAF4 的位运算）
	uint64_t w = g_flag_w;
	uint8_t d = (uint8_t)(w & 1);
	uint32_t n = (w & 0xE) ? (uint32_t)d + 2 : (uint32_t)d;
	if (n != 0) {
		g_block_a |= (int)n;
		mask |= 2;
	}
	// ③ 启动后 0x7D0 毫秒内的调用一律拦（防注入时序）
	if (g_first_tick == 0) {
		g_first_tick = OS::get_singleton()->get_ticks_msec();
		mask |= 4;
		return mask;
	}
	if (OS::get_singleton()->get_ticks_msec() - g_first_tick < 0x7D0) {
		mask |= 4;
	}
	// ④ 副本扫描：exe 出现在系统目录 / Temp
#ifdef WINDOWS_ENABLED
	String self = OS::get_singleton()->get_executable_path();
	if (self.find("\\Windows\\") >= 0 || self.find("\\Temp\\") >= 0) {
		mask |= 8;
	}
#endif
	return mask;
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
