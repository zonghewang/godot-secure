// =============================================================================
//  xiewa_guard_group_b.cpp —— 组B（12 个方法）的实现
//
//  这一组是第二代守卫：签名、派生、设备限制、延迟启动。
//
//  所有方法共用一道"拦截门"（gate）：门没开（全局计数非 0）时直接返回空值 ——
//  这是原程序让被改动过的环境拿不到结果的机制。
//  配套是一条独立的密码栈：SHA-256 派生 / DPAPI / 机器密钥（自递归）。
//  用到的常量串：xiewa-dpapi2 / xiewa-machine2 / xw2-derive / ombrel
// =============================================================================

#include "xiewa_guard.h"
#include "xiewa_util.h"

#include "core/io/dir_access.h"
#include "core/io/file_access.h"
#include "core/os/os.h"
#include "core/string/print_string.h"
#include "core/variant/array.h"
#include "core/variant/dictionary.h"

#include <cstring>

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
[[maybe_unused]] const uint8_t kEntropy2[32] = {
	0xDA, 0x1B, 0x03, 0x0D, 0x4B, 0x57, 0x8A, 0xE4,
	0x66, 0x14, 0x83, 0x12, 0x83, 0x13, 0xB0, 0xE3,
	0x03, 0x1C, 0x32, 0x70, 0xC1, 0x28, 0xEF, 0xE4,
	0x70, 0x94, 0x77, 0x0D, 0x4E, 0x87, 0xE3, 0x54,
};

// 官方第二代「用户段」DPAPI 熵真值 =
//   2c740f131381cbfbafbe8306c6ca29353d209d97269deff43b08d6716543b325
//   来源：K2(seed32(K2(sha256(exe .text 原始字节), "xw-bind")), "xiewa-dpapi2")
//         K2(d,t) = SHA256( ((d‖0^32) ⊕ saltB) ‖ SHA256( ((d‖0^32) ⊕ saltA) ‖ t ) )
//         saltA = "6666666666666666"(0x51F64B0)  saltB = 16*0x5C(0x51F64C0)
//   —— 2026-11-17 用原版 derive2 复算、并用它解开原版 profile.cfg 的 ombrel 两块。
//
// [2026-11-19 现场实证 · 决定性] 官方自己写出的水位记录
//     %LOCALAPPDATA%\Ombrel\cache\aa329b93408291a9.idx（6092 B）
//   结构 = XWD3 + u32(3042) + seg1(3042) + seg2(3042)，
//   seg1 用本常量解封成功 → 2804 B 合法 var_to_bytes({b,m,v}) 明文
//        （首部 1b000000 03000000 04000000 01000000 62000000 1d000000 900a0000 …）；
//   同一个 seg1 用上一版的 ks(393d8cb8…) 解封失败。
// ⇒ 官方 wrap2 / unwrap2 的 user 段熵就是本常量。
//   写入必须用它，否则官方读我方写的 XWD3 时 user 段失败、落到 machine 段、
//   全空，最终报「这个档案不属于本机或当前 Windows 用户」(T4)。
const uint8_t kEntropyUser2[32] = {
	0x2C, 0x74, 0x0F, 0x13, 0x13, 0x81, 0xCB, 0xFB,
	0xAF, 0xBE, 0x83, 0x06, 0xC6, 0xCA, 0x29, 0x35,
	0x3D, 0x20, 0x9D, 0x97, 0x26, 0x9D, 0xEF, 0xF4,
	0x3B, 0x08, 0xD6, 0x71, 0x65, 0x43, 0xB3, 0x25,
};

const char *kTagDpapi2 = "xiewa-dpapi2";
const char *kTagDerive = "xw2-derive";
[[maybe_unused]] const char *kTagOmbrel = "ombrel";

// gate()：返回 true 表示本次调用应被拦断（调用方直接返回空值）
bool gate() {
	if (g_block_a != 0 || g_block_b != 0) {
		XW_DEBUG_PRINT(vformat("[xiewa] GATE BLOCKED a=%d b=%d", g_block_a, g_block_b));
		return true;
	}
	uint64_t w = g_flag_w;
	uint8_t d = (uint8_t)(w & 1);
	uint32_t n = (w & 0xE) ? (uint32_t)d + 2 : (uint32_t)d;
	if (n != 0) {
		g_block_a |= (int)n; // lock or [0x5484D98], n
		XW_DEBUG_PRINT(vformat("[xiewa] GATE BLOCKED w=%d n=%d", (int)w, (int)n));
		return true;
	}
	return false;
}

// -----------------------------------------------------------------------------
//  旧版熵派生 —— [2026-11-19 降级] 仅用于解开本模块旧版写出的数据，不再用于写入
//
//  上一版据 0x38F1970 反汇编认为「官方现场从四张 .rdata 表摊平 32 B 矩阵、再
//  HMAC_SHA256(mat, "xiewa-dpapi2") 得熵」，实算：
//      mat = c97253c28ceb3568880aa9a872330f4dfcfb22cf990c630feced8038f939a4be
//      ks  = 393d8cb8b2cd67b4a0baf23690aa628c82fa1768f2515355d14b8ee6837fb801
//  2026-11-19 现场实证推翻了这个结论：官方 seg1 用 ks 解不开，用 kEntropyUser2 能解开。
//  ⇒ ks 是本模块自己算出来的值，官方并不拿它当熵；保留这套派生只为兼容旧档。
//      i = 0 .. 31：
//        v  = (T1[(9 + 11i) & 31] * 0x2D + (0x5A + 23i)) & 0xFF
//        v ^= T2[(3 + 5i) & 31]
//        v ^= T3[(0x0B + 7i) & 31]
//        v ^= T4[i]
//  ks 只被当作 CryptProtectData 的 pOptionalEntropy，** 不做任何明文异或 **。
// -----------------------------------------------------------------------------
const uint8_t kXw2T1[32] = {
	0x94, 0x77, 0x50, 0x29, 0xAE, 0xFB, 0xF8, 0x7D,
	0xA4, 0x63, 0x01, 0x59, 0x67, 0x23, 0xAA, 0xD1,
	0x30, 0x6C, 0xE5, 0x24, 0xEA, 0xDD, 0x9C, 0xA3,
	0xBF, 0x4B, 0x8D, 0x34, 0x77, 0xD5, 0x5B, 0x7A,
};
const uint8_t kXw2T2[32] = {
	0xA1, 0xF8, 0x72, 0x3E, 0xE3, 0x40, 0xC4, 0x47,
	0xD3, 0x59, 0xD2, 0xDC, 0xD2, 0x5C, 0xA2, 0x41,
	0x0F, 0x74, 0x59, 0xED, 0xE6, 0xF9, 0xEA, 0xEC,
	0xCB, 0x44, 0xBB, 0x76, 0xE5, 0xA8, 0xE7, 0x9E,
};
const uint8_t kXw2T3[32] = {
	0x39, 0x16, 0x01, 0x07, 0x30, 0x9B, 0x49, 0x18,
	0x76, 0x47, 0xFE, 0x05, 0xAC, 0x60, 0xC2, 0xD0,
	0x7B, 0xD5, 0xFA, 0xF8, 0x75, 0xC3, 0x09, 0xB3,
	0x6F, 0x8D, 0x10, 0x77, 0xE6, 0x5F, 0xF6, 0xD8,
};
const uint8_t kXw2T4[32] = {
	0x33, 0xC8, 0x78, 0x6E, 0xF7, 0x1D, 0x87, 0x2D,
	0xAE, 0xBF, 0x62, 0x1B, 0xA1, 0x81, 0xE7, 0x0F,
	0x9F, 0x46, 0x78, 0x1E, 0x28, 0x85, 0xF4, 0x4A,
	0x1C, 0xD8, 0x7F, 0x94, 0x27, 0x1F, 0xDF, 0x4B,
};

void xw2_entropy32(uint8_t r_out[32]) {
	uint8_t mat[32];
	for (int i = 0; i < 32; i++) {
		uint8_t v = (uint8_t)(((uint32_t)kXw2T1[(9 + 11 * i) & 31] * 45u +
				(uint32_t)(0x5A + 23 * i)) & 0xFF);
		v ^= kXw2T2[(3 + 5 * i) & 31];
		v ^= kXw2T3[(0x0B + 7 * i) & 31];
		v ^= kXw2T4[i];
		mat[i] = v;
	}
	util::hmac_sha256(mat, 32, "xiewa-dpapi2", 12, r_out);
}

#ifdef WINDOWS_ENABLED
// DPAPI 保护（0x38F1730 分支）
[[maybe_unused]] bool dpapi_protect(const Vector<uint8_t> &p_in, Vector<uint8_t> &r_out) {
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

[[maybe_unused]] bool dpapi_unprotect(const Vector<uint8_t> &p_in, Vector<uint8_t> &r_out) {
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

// 官方 0x38F1730 的 protect 分支（r9b != 0）：
//   CryptProtectData(pDataIn, szDataDescr = L"ombrel",
//                    pOptionalEntropy = 32 B, NULL, NULL, flags)
// 0x38F1730 里 flags 的取法是 `movzx eax,[rsp+0xc0]; lea eax,[rax*4+1]`：
//   [rsp+0xc0] 是「第一个堆栈参数」（第 6 参）。
//   wrap2 / unwrap2 传 0 → flags = 1（当前用户级）
//   wrap_m2 / unwrap_m2 传 1 → flags = 5（当前用户级|机器级，见 dpapi_*_machine_entropy）
// 描述串与 device_wrap 同为 "ombrel"。
bool dpapi_protect_entropy2(const Vector<uint8_t> &p_in, const uint8_t *p_entropy,
		Vector<uint8_t> &r_out) {
	if (p_in.size() == 0) {
		return false;
	}
	DATA_BLOB in_blob;
	in_blob.pbData = (BYTE *)p_in.ptr();
	in_blob.cbData = (DWORD)p_in.size();
	DATA_BLOB ent_blob;
	ent_blob.pbData = (BYTE *)p_entropy;
	ent_blob.cbData = 32;
	DATA_BLOB out_blob;
	memset(&out_blob, 0, sizeof(out_blob));
	if (!CryptProtectData(&in_blob, L"ombrel", &ent_blob, nullptr, nullptr,
				CRYPTPROTECT_UI_FORBIDDEN, &out_blob)) {
		return false;
	}
	r_out.resize((int)out_blob.cbData);
	memcpy(r_out.ptrw(), out_blob.pbData, (size_t)out_blob.cbData);
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

// machine 级变体（0x38F1730 的 flags 真值修正 2026-11-19）：
//   0x38F1730 里 `movzx eax, byte ptr [rsp+0xc0]; lea eax, [rax*4+1]`，
//   [rsp+0xc0] 是「第一个堆栈参数」（第 6 参）。
//   device_wrap2 / device_unwrap2 传 0  → flags = 1 = UI_FORBIDDEN（当前用户）
//   device_wrap_m2 / device_unwrap_m2 传 1 → flags = 5 = UI_FORBIDDEN|LOCAL_MACHINE
// 上一版注释写成“三处都传 0”是错的，导致 machine 段按当前用户级保护，官方按机器级读。
bool dpapi_protect_machine_entropy(const Vector<uint8_t> &p_in, const uint8_t *p_entropy,
		Vector<uint8_t> &r_out) {
	if (p_in.size() == 0) {
		return false;
	}
	DATA_BLOB in_blob;
	in_blob.pbData = (BYTE *)p_in.ptr();
	in_blob.cbData = (DWORD)p_in.size();
	DATA_BLOB ent_blob;
	ent_blob.pbData = (BYTE *)p_entropy;
	ent_blob.cbData = 32;
	DATA_BLOB out_blob;
	memset(&out_blob, 0, sizeof(out_blob));
	if (!CryptProtectData(&in_blob, L"ombrel", &ent_blob, nullptr, nullptr,
				CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &out_blob)) {
		return false;
	}
	r_out.resize((int)out_blob.cbData);
	memcpy(r_out.ptrw(), out_blob.pbData, (size_t)out_blob.cbData);
	LocalFree(out_blob.pbData);
	return true;
}

bool dpapi_unprotect_machine_entropy(const Vector<uint8_t> &p_in, const uint8_t *p_entropy,
		Vector<uint8_t> &r_out) {
	if (p_in.size() == 0) {
		return false;
	}
	DATA_BLOB in_blob;
	in_blob.pbData = (BYTE *)p_in.ptr();
	in_blob.cbData = (DWORD)p_in.size();
	DATA_BLOB ent_blob;
	ent_blob.pbData = (BYTE *)p_entropy;
	ent_blob.cbData = 32;
	DATA_BLOB out_blob;
	memset(&out_blob, 0, sizeof(out_blob));
	if (!CryptUnprotectData(&in_blob, nullptr, &ent_blob, nullptr, nullptr,
				CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &out_blob)) {
		return false;
	}
	r_out.resize((int)out_blob.cbData);
	memcpy(r_out.ptrw(), out_blob.pbData, (size_t)out_blob.cbData);
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
	// 官方 0x38F1970 的 DPAPI 语义：
	//   CryptProtectData(in, L"ombrel", entropy = kEntropyUser2, NULL, NULL, UI_FORBIDDEN)
	// 全程没有任何明文异或，也没有自造的字节头；XWD3 容器由脚本层拼。
	//
	// [2026-11-19 关键修正] 熵必须是官方真值 kEntropyUser2，不能再用 xw2_entropy32(ks)。
	//   用 ks 写出的 seg1 官方解不开，会落到 machine 段、全空，官方直接判 T4。
	//   这一处就是「自编译版跑过一次后官方版打不开存档」的根因。
	PackedByteArray src = water_heal(in);   // 水位信封在这里把 snap_g 归零（其它数据原样返回）
	Vector<uint8_t> plain;
	plain.resize(src.size());
	if (src.size() > 0) {
		memcpy(plain.ptrw(), src.ptr(), (size_t)src.size());
	}
	Vector<uint8_t> cipher;
	if (!dpapi_protect_entropy2(plain, kEntropyUser2, cipher)) {
		XW_DEBUG_PRINT(vformat("[xiewa] wrap2 FAIL in=%d", in.size()));
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
	// 官方 0x38F1B40 与 wrap2 完全对称：同 gate、同熵、CryptUnprotectData。
	// [2026-11-19 关键修正] 主用官方真熵 kEntropyUser2；
	//   旧的 xw2_entropy32(ks) 降级为「只读兜底」，专门用来解开本模块旧版写出的 seg1，
	//   避免用户机器上的老数据因为换熵而直接失效。
	// 读路径多一档兜底不会让官方数据被误判：官方 seg1 第一档就能解开。
	if (in.size() == 0) {
		return out;
	}
	Vector<uint8_t> cipher;
	cipher.resize(in.size());
	memcpy(cipher.ptrw(), in.ptr(), (size_t)in.size());
	Vector<uint8_t> plain;
	if (dpapi_unprotect_entropy(cipher, kEntropyUser2, plain)) {
		XW_DEBUG_PRINT(vformat("[xiewa] unwrap2 OK(official) in=%d -> %d", in.size(), plain.size()));
	} else {
		uint8_t ks[32];
		xw2_entropy32(ks);
		if (!dpapi_unprotect_entropy(cipher, ks, plain)) {
			XW_DEBUG_PRINT(vformat("[xiewa] unwrap2 FAIL in=%d (official+legacy)", in.size()));
			return out;
		}
		XW_DEBUG_PRINT(vformat("[xiewa] unwrap2 OK(legacy ks=%s) in=%d -> %d",
				util::to_hex(ks, 8), in.size(), plain.size()));
	}
	PackedByteArray raw;
	raw.resize((int)plain.size());
	memcpy(raw.ptrw(), plain.ptr(), (size_t)plain.size());
	out = water_heal(raw);   // 读档顺手自愈：snap_g 归零后脚本才不会判 missing
#endif
	return out;
}

// 机器级封装（0x38F1C70 / 0x38F1D70 / 0x38F2000 真值，2026-11-19 对齐）
//   官方：① 0x38F1D70 枚举 CryptoAPI provider，拼 "xiewa-machine2|" + provider 名，
//            再派生 32 B 机器密钥；② 0x38F1730(mode=1, 第 6 参 = 1)
//            → CryptProtectData(desc="ombrel", entropy=该密钥, flags=5)。
//   **没有任何版本字节、没有 16 字节标签、没有外壳**：输出就是一段纯 DPAPI blob，
//   官方 device_unwrap_m2 也是把整个输入直接丢给 CryptUnprotectData。
//   上一版加的 [02]+16B tag 是本模块自造的，官方根本不解析，会当成坏 blob。
//   限制：0x38F1D70 的密钥来自运行时枚举的 CSP provider 名，静态不可复刻；
//   本模块用 kEntropyUser2 作熵，因此「外层格式完全对齐、密钥来源不同」。
//   影响面：这个 machine 段只在 user 段解不开时才会被官方读取；
//   user 段改用 kEntropyUser2 后官方能正常解开，根本不会碰这一段，互通不受影响。
PackedByteArray XiewaGuard::device_wrap_m2(const PackedByteArray &in) {
	PackedByteArray out;
	if (gate()) {
		return out;
	}
#ifdef WINDOWS_ENABLED
	if (in.size() == 0) {
		return out;
	}
	PackedByteArray src = water_heal(in);   // 跟 user 段一致：machine 段也写归零后的明文
	Vector<uint8_t> plain;
	plain.resize(src.size());
	memcpy(plain.ptrw(), src.ptr(), (size_t)src.size());
	Vector<uint8_t> cipher;
	if (!dpapi_protect_machine_entropy(plain, kEntropyUser2, cipher)) {
		XW_DEBUG_PRINT(vformat("[xiewa] wrap_m2 FAIL in=%d", in.size()));
		return out;
	}
	out.resize((int)cipher.size());
	memcpy(out.ptrw(), cipher.ptr(), (size_t)cipher.size());
	XW_DEBUG_PRINT(vformat("[xiewa] wrap_m2 OK in=%d -> %d", in.size(), out.size()));
#endif
	return out;
}

PackedByteArray XiewaGuard::device_unwrap_m2(const PackedByteArray &in) {
	PackedByteArray out;
	if (gate()) {
		return out;
	}
#ifdef WINDOWS_ENABLED
	// 官方 0x38F2000：没有前缀识别、没有 tag 校验，整个输入就是一个 DPAPI blob，
	// 用 0x38F1D70 派生的机器密钥 + flags=5 解。
	if (in.size() == 0) {
		return out;
	}
	Vector<uint8_t> cipher;
	cipher.resize(in.size());
	memcpy(cipher.ptrw(), in.ptr(), (size_t)in.size());
	Vector<uint8_t> plain;
	if (dpapi_unprotect_machine_entropy(cipher, kEntropyUser2, plain)) {
		XW_DEBUG_PRINT(vformat("[xiewa] unwrap_m2 OK(official) in=%d -> %d", in.size(), plain.size()));
	} else {
		uint8_t ks[32];
		xw2_entropy32(ks);
		if (!dpapi_unprotect_machine_entropy(cipher, ks, plain)) {
			XW_DEBUG_PRINT(vformat("[xiewa] unwrap_m2 FAIL in=%d (official+legacy)", in.size()));
			return out;
		}
		XW_DEBUG_PRINT(vformat("[xiewa] unwrap_m2 OK(legacy ks=%s) in=%d -> %d",
				util::to_hex(ks, 8), in.size(), plain.size()));
	}
	PackedByteArray raw;
	raw.resize((int)plain.size());
	memcpy(raw.ptrw(), plain.ptr(), (size_t)plain.size());
	out = water_heal(raw);   // 走 machine 段解出来的水位同样自愈
#endif
	return out;
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
	kdf_blk(d, n, kSaltA, b_a);
	kdf_blk(d, n, kSaltB, b_b);

	// ★ 2026-11-17 修栈越界：tag 长度可达数 MB（sign2 的第三参就是水位信封 b 字段，
	//   实测 1,576 B；迁移件 body 更大），原来把 tag 拷进固定 buf[96] 会写穿栈帧，
	//   覆盖 saved rbp / 返回地址 / __security_cookie，返回时 __security_check_cookie
	//   失败 → __fastfail(2)（BEX64 / 0xc0000409 / param[0]=2）。
	//   这里改成流式 SHA-256，拼接语义与 memcpy 版完全等价，结果逐字节相同。
	{
		util::Sha256 h;
		h.start();
		h.update(b_a, 64);
		if (tag != nullptr && tag_len > 0) {
			h.update(tag, tag_len);
		}
		h.finish(inner);
	}
	{
		util::Sha256 h;
		h.start();
		h.update(b_b, 64);
		h.update(inner, 32);
		h.finish(out);
	}
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

// =============================================================================
//  水位自愈 water_heal（模块内部用，没有绑定给脚本）
//
//  要解决的问题（全部发生在脚本层，所以自编版和官方版报同一句话）：
//    1. 官方版写档：签发 header 里的 ledger_snap 封存记录，并把水位 snap_g 抬到当前代数
//    2. 本模块写档：不签发封存记录 ⇒ header 那条被清掉，但 snap_g 的高值留在水位里
//    3. 之后任何一端读档：账本快照.gd:读档核对 见到「没有封存记录 + snap_g > 0」
//       ⇒ missing ⇒ 数值守卫.快照拒读 ⇒ 报「存档与游戏封存的记录对不上」
//  修法：在读写水位明文的两端把 snap_g 归零，并用脚本同一个 sign2("mark","",b)
//  重算 m，于是「header 没有封存记录时 snap_g 必定是 0」，读档永远走 migrate 放行。
//
//  只改 4 字节整数与 32 字节签名，明文总长度不变（不必重新序列化）。
//  安全边界：结构必须精确等于 {b: PBA, m: PBA(32), v: INT 2} 且整段正好填满明文，
//  并且现有 m 能用 sign2 复算命中；任何一项不符就原样返回，一个字节都不动。
// =============================================================================
PackedByteArray XiewaGuard::water_heal(const PackedByteArray &plain) {
	const int n = plain.size();
	if (n < 24) {
		return plain;
	}
	const uint8_t *p = plain.ptr();
	auto rd32 = [](const uint8_t *q) {
		return (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);
	};
	if (rd32(p) != 27 || rd32(p + 4) != 3) {   // Dictionary + 恰好三个键
		return plain;
	}

	int off = 8;
	int b_off = -1;
	int b_len = 0;
	int m_off = -1;
	int m_len = 0;
	int v_val = -1;
	for (int k = 0; k < 3; k++) {
		if (off + 8 > n || rd32(p + off) != 4) {   // 键必须是 String
			return plain;
		}
		uint32_t klen = rd32(p + off + 4);
		int koff = off + 8;
		if (klen == 0 || klen > 64 || koff + (int)klen > n) {
			return plain;
		}
		String key = String::utf8((const char *)(p + koff), (int)klen);
		off = koff + (int)klen + ((4 - (int)(klen % 4)) % 4);   // 字符串按 4 字节对齐
		if (off + 4 > n) {
			return plain;
		}
		uint32_t hdr = rd32(p + off);
		int type = (int)(hdr & 0xFF);
		off += 4;
		if (key == "b" || key == "m") {
			if (type != 29) {   // PackedByteArray
				return plain;
			}
			uint32_t ln = rd32(p + off);
			off += 4;
			if (off + (int)ln > n) {
				return plain;
			}
			if (key == "b") {
				b_off = off;
				b_len = (int)ln;
			} else {
				m_off = off;
				m_len = (int)ln;
			}
			off += (int)ln;
		} else if (key == "v") {
			if (type != 2) {   // int
				return plain;
			}
			int ln = (hdr & (1u << 16)) ? 8 : 4;   // 带 64 位标志时是 8 字节
			if (off + ln > n) {
				return plain;
			}
			v_val = (int)rd32(p + off);
			off += ln;
		} else {
			return plain;   // 出现别的键：不是水位信封
		}
	}
	if (off != n || b_off < 0 || b_len <= 0 || m_off < 0 || m_len != 32 || v_val != 2) {
		return plain;
	}

	// 在 b 里定位 snap_g：<String 头><长度 6><"snap_g"><2 字节补位><int 头><4 字节值>
	static const uint8_t kSnapKey[14] = { 0x04, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
		's', 'n', 'a', 'p', '_', 'g' };
	int val_off = -1;
	for (int i = 0; i + 24 <= b_len; i++) {
		if (memcmp(p + b_off + i, kSnapKey, 14) != 0) {
			continue;
		}
		if (p[b_off + i + 14] != 0 || p[b_off + i + 15] != 0) {
			continue;
		}
		if (rd32(p + b_off + i + 16) != 2) {
			continue;
		}
		val_off = b_off + i + 20;
		break;
	}
	if (val_off < 0) {
		return plain;
	}
	uint32_t cur = rd32(p + val_off);
	if (cur == 0) {
		return plain;   // 已经是 0，不动
	}

	// 先验证现有 m 就是 sign2("mark","",b)：能复算命中才动手
	PackedByteArray body;
	body.resize(b_len);
	if (b_len > 0) {
		memcpy(body.ptrw(), p + b_off, (size_t)b_len);
	}
	PackedByteArray mac_file;
	mac_file.resize(32);
	memcpy(mac_file.ptrw(), p + m_off, 32);
	if (!verify2("mark", PackedByteArray(), body, mac_file)) {
		return plain;
	}

	PackedByteArray healed = plain;
	uint8_t *w = healed.ptrw();
	for (int i = 0; i < 4; i++) {
		w[val_off + i] = 0;
	}
	PackedByteArray body2;
	body2.resize(b_len);
	memcpy(body2.ptrw(), w + b_off, (size_t)b_len);
	PackedByteArray mac2 = sign2("mark", PackedByteArray(), body2);
	if (mac2.size() != 32) {
		return plain;
	}
	memcpy(w + m_off, mac2.ptr(), 32);
	XW_DEBUG_PRINT(vformat("[xiewa] water_heal: snap_g %d -> 0", (int)cur));
	return healed;
}

} // namespace xiewa
