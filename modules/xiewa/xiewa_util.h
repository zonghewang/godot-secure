// =============================================================================
//  xiewa_util.h —— 模块内部公共工具（全部 inline，无单独编译单元）
//
//  提供：SHA-256 / HMAC-SHA-256 / hex / 宽字符转换 / 注册表读写 / 常量时间比较
//  只依赖 Win32 + Godot core，不引入外部库。
// =============================================================================

#pragma once

#include "core/core_bind.h" // Marshalls
#include "core/io/marshalls.h" // decode_variant
#include "core/string/print_string.h" // print_line（XW_DEBUG_PRINT 用）
#include "core/string/ustring.h"
#include "core/templates/vector.h"

#include <stdint.h>
#include <string.h>
#include <string>

#ifdef WINDOWS_ENABLED
#include <windows.h>
#endif

// -----------------------------------------------------------------------------
//  调试输出开关
//
//  XW_DEBUG_PRINT(...)：默认只在 debug 构建（template_debug）里真正打印；
//  template_release 下展开成空语句 —— 连参数里的 vformat 拼接都不会执行，
//  所以 release 版不会往 godot.log 里写任何 [xiewa] 行。
//
//  排障需要时：把下面的 XW_DEBUG_FORCE 改成 1，release 版也会打印，改回 0 即恢复。
//  用法与 print_line 一致：
//      XW_DEBUG_PRINT(vformat("[xiewa] xxx %d", n));
// -----------------------------------------------------------------------------
#ifndef XW_DEBUG_FORCE
#define XW_DEBUG_FORCE 0 // 1 = 强制打印（release 也打印），0 = 跟随构建类型
#endif

#if XW_DEBUG_FORCE || defined(DEBUG_ENABLED)
#define XW_DEBUG_PRINT(...) print_line(__VA_ARGS__)
#else
#define XW_DEBUG_PRINT(...) ((void)0)
#endif

namespace xiewa {
namespace util {

// -----------------------------------------------------------------------------
// SHA-256（FIPS 180-4）
// -----------------------------------------------------------------------------
struct Sha256 {
	uint32_t h[8];
	uint64_t total;
	uint8_t buf[64];
	uint32_t buf_len;

	void start() {
		h[0] = 0x6a09e667u; h[1] = 0xbb67ae85u; h[2] = 0x3c6ef372u; h[3] = 0xa54ff53au;
		h[4] = 0x510e527fu; h[5] = 0x9b05688cu; h[6] = 0x1f83d9abu; h[7] = 0x5be0cd19u;
		total = 0;
		buf_len = 0;
	}
	void block(const uint8_t *p);
	void update(const void *p_data, size_t p_len);
	void finish(uint8_t r_out[32]);
};

inline uint32_t sha_rotr(uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

inline void Sha256::block(const uint8_t *p) {
	static const uint32_t K[64] = {
		0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
		0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
		0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
		0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
		0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
		0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
		0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
		0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
	};
	uint32_t w[64];
	for (int i = 0; i < 16; i++) {
		w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
				((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
	}
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = sha_rotr(w[i - 15], 7) ^ sha_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = sha_rotr(w[i - 2], 17) ^ sha_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
	for (int i = 0; i < 64; i++) {
		uint32_t S1 = sha_rotr(e, 6) ^ sha_rotr(e, 11) ^ sha_rotr(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t t1 = hh + S1 + ch + K[i] + w[i];
		uint32_t S0 = sha_rotr(a, 2) ^ sha_rotr(a, 13) ^ sha_rotr(a, 22);
		uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = S0 + mj;
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

inline void Sha256::update(const void *p_data, size_t p_len) {
	const uint8_t *p = (const uint8_t *)p_data;
	total += p_len;
	while (p_len > 0) {
		uint32_t take = 64 - buf_len;
		if (take > p_len) {
			take = (uint32_t)p_len;
		}
		memcpy(buf + buf_len, p, take);
		buf_len += take;
		p += take;
		p_len -= take;
		if (buf_len == 64) {
			block(buf);
			buf_len = 0;
		}
	}
}

inline void Sha256::finish(uint8_t r_out[32]) {
	uint64_t bits = total * 8;
	uint8_t one = 0x80;
	update(&one, 1);
	uint8_t zero = 0;
	while (buf_len != 56) {
		update(&zero, 1);
	}
	uint8_t len[8];
	for (int i = 0; i < 8; i++) {
		len[i] = (uint8_t)((bits >> (56 - i * 8)) & 0xFF);
	}
	update(len, 8);
	for (int i = 0; i < 8; i++) {
		r_out[i * 4 + 0] = (uint8_t)((h[i] >> 24) & 0xFF);
		r_out[i * 4 + 1] = (uint8_t)((h[i] >> 16) & 0xFF);
		r_out[i * 4 + 2] = (uint8_t)((h[i] >> 8) & 0xFF);
		r_out[i * 4 + 3] = (uint8_t)(h[i] & 0xFF);
	}
}

inline void sha256(const void *p_data, size_t p_len, uint8_t r_out[32]) {
	Sha256 c;
	c.start();
	c.update(p_data, p_len);
	c.finish(r_out);
}

// HMAC-SHA-256（RFC 2104）
inline void hmac_sha256(const void *p_key, size_t p_key_len, const void *p_msg, size_t p_msg_len, uint8_t r_out[32]) {
	uint8_t k[64];
	memset(k, 0, sizeof(k));
	if (p_key_len > 64) {
		sha256(p_key, p_key_len, k);
	} else {
		memcpy(k, p_key, p_key_len);
	}
	uint8_t ipad[64], opad[64];
	for (int i = 0; i < 64; i++) {
		ipad[i] = (uint8_t)(k[i] ^ 0x36);
		opad[i] = (uint8_t)(k[i] ^ 0x5C);
	}
	uint8_t inner[32];
	Sha256 c;
	c.start();
	c.update(ipad, 64);
	c.update(p_msg, p_msg_len);
	c.finish(inner);

	Sha256 o;
	o.start();
	o.update(opad, 64);
	o.update(inner, 32);
	o.finish(r_out);
}

inline void hmac_sha256(const String &p_key, const String &p_msg, uint8_t r_out[32]) {
	CharString k = p_key.utf8();
	CharString m = p_msg.utf8();
	hmac_sha256(k.get_data(), (size_t)k.length(), m.get_data(), (size_t)m.length(), r_out);
}

// -----------------------------------------------------------------------------
// hex / 字节
// -----------------------------------------------------------------------------
inline String to_hex(const uint8_t *p_data, size_t p_len) {
	// Godot 的 String 没有 resize()，走 char 缓冲 + String::utf8 组串。
	static const char *digits = "0123456789abcdef";
	Vector<char> buf;
	buf.resize((int)(p_len * 2 + 1));
	char *w = buf.ptrw();
	for (size_t i = 0; i < p_len; i++) {
		w[i * 2] = digits[p_data[i] >> 4];
		w[i * 2 + 1] = digits[p_data[i] & 0x0F];
	}
	w[p_len * 2] = 0;
	return String::utf8(w, (int)(p_len * 2));
}

inline String to_hex32(const uint8_t p_in[32]) {
	return to_hex(p_in, 32);
}

inline Vector<uint8_t> from_hex(const String &p_hex) {
	Vector<uint8_t> out;
	if (p_hex.length() % 2 != 0) {
		return out;
	}
	out.resize(p_hex.length() / 2);
	uint8_t *w = out.ptrw();
	int i = 0;
	while (i < p_hex.length()) {
		int hi = -1, lo = -1;
		char a = (char)p_hex[i], b = (char)p_hex[i + 1];
		hi = (a >= '0' && a <= '9') ? a - '0' : (a >= 'a' && a <= 'f') ? a - 'a' + 10 : (a >= 'A' && a <= 'F') ? a - 'A' + 10 : -1;
		lo = (b >= '0' && b <= '9') ? b - '0' : (b >= 'a' && b <= 'f') ? b - 'a' + 10 : (b >= 'A' && b <= 'F') ? b - 'A' + 10 : -1;
		if (hi < 0 || lo < 0) {
			out.clear();
			return out;
		}
		w[i / 2] = (uint8_t)((hi << 4) | lo);
		i += 2;
	}
	return out;
}

// -----------------------------------------------------------------------------
//  [修正 2026-11-16] 密文 / 明文的形态判定
//
//  0x340D7E0 / 0x38F1970 两代 device_wrap 的产物都是 CryptProtectData 的
//  DATA_BLOB，头部固定为 01 00 00 00 + provider GUID {df9d8cd0-1501-11d1-...}。
//  我方解不开（熵来自运行期填充表）时若继续按 XOR 解，会吐出一串"长度相同但
//  首 4 字节非法"的字节，脚本侧 bytes_to_var() 立刻报
//      Condition "(header & 0xFF) >= Variant::VARIANT_MAX"
//  因此解封函数必须先判定形态：DPAPI 形态一律返回空，XOR 产物必须过 Variant 头校验。
// -----------------------------------------------------------------------------
inline bool looks_like_dpapi(const uint8_t *p_data, int p_len) {
	if (p_data == nullptr || p_len < 8) {
		return false;
	}
	static const uint8_t sig[8] = { 0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf };
	return memcmp(p_data, sig, 8) == 0;
}

// Variant 序列化流的首 4 字节 = u32 header，低字节为 Variant::Type（< VARIANT_MAX=39）
inline bool looks_like_variant(const uint8_t *p_data, int p_len) {
	if (p_data == nullptr || p_len < 5) {
		return false;
	}
	uint32_t header = (uint32_t)p_data[0] | ((uint32_t)p_data[1] << 8) |
			((uint32_t)p_data[2] << 16) | ((uint32_t)p_data[3] << 24);
	return (header & 0xFFu) < 39u;
}

inline bool looks_like_dpapi(const Vector<uint8_t> &p_in) {
	return looks_like_dpapi(p_in.ptr(), p_in.size());
}

inline bool looks_like_variant(const Vector<uint8_t> &p_in) {
	return looks_like_variant(p_in.ptr(), p_in.size());
}

// 注：PackedByteArray 即 Vector<uint8_t> 的别名，无需另加重载

// -----------------------------------------------------------------------------
//  [修正 2026-11-17] 静默预筛：脚本侧 device_wrap 包的一直是 var_to_bytes(dict)，
//  形如 {"b":PBA,"m":PBA[,"v":int]}。先按 marshal 布局做纯字节预筛，
//  只有通过预筛才真正调用 decode_variant —— 否则 decode_variant 自己会打印
//      Condition "((int32_t)(count)) < 0 || ..." → ERR_INVALID_DATA  (marshalls.cpp:976)
//  垃圾字节被送进解码器时会再刷一遍 ERROR，这正是 2026-11-17 日志里新出现的那批。
//  未类型化 Dictionary 布局：header(4) + count(4) + [key header(4)+u32 len+bytes(+pad)] …
// -----------------------------------------------------------------------------
inline uint32_t read_u32le(const uint8_t *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

inline bool dict_plain_precheck(const uint8_t *p_data, int p_len) {
	if (p_data == nullptr || p_len < 24) {
		return false;
	}
	uint32_t header = read_u32le(p_data);
	if ((header & 0xFFu) != 27u) { // Variant::DICTIONARY
		return false;
	}
	uint32_t count = read_u32le(p_data + 4) & 0x7FFFFFFFu;
	if (count < 1u || count > 16u) {
		return false;
	}
	if ((read_u32le(p_data + 8) & 0xFFu) != 4u) { // 键必须是 String
		return false;
	}
	uint32_t klen = read_u32le(p_data + 12);
	if (klen != 1u) {
		return false;
	}
	uint8_t k = p_data[16];
	if (k != 'b' && k != 'm' && k != 'v') { // 脚本固定这三个键
		return false;
	}
	return true;
}

// 强校验：预筛通过后再用与脚本 bytes_to_var() 完全相同的解码器完整解一遍
inline bool plain_is_decodable(const uint8_t *p_data, int p_len) {
	if (!dict_plain_precheck(p_data, p_len)) {
		return false;
	}
	Variant v;
	int used = 0;
	Error err = decode_variant(v, p_data, p_len, &used, false, 0);
	if (err != OK || used != p_len) {
		return false;
	}
	return v.get_type() == Variant::DICTIONARY;
}

inline bool plain_is_decodable(const Vector<uint8_t> &p_in) {
	return plain_is_decodable(p_in.ptr(), p_in.size());
}

// 常量时间比较（避免时序侧信道）
inline bool ct_equal(const uint8_t *p_a, const uint8_t *p_b, size_t p_len) {
	uint8_t diff = 0;
	for (size_t i = 0; i < p_len; i++) {
		diff |= (uint8_t)(p_a[i] ^ p_b[i]);
	}
	return diff == 0;
}

inline bool ct_equal(const String &p_a, const String &p_b) {
	if (p_a.length() != p_b.length()) {
		return false;
	}
	uint8_t diff = 0;
	for (int i = 0; i < p_a.length(); i++) {
		diff |= (uint8_t)(p_a[i] ^ p_b[i]);
	}
	return diff == 0;
}

// -----------------------------------------------------------------------------
// UTF-8 → UTF-16（Win32 用）
// -----------------------------------------------------------------------------
#ifdef WINDOWS_ENABLED
inline std::wstring wide(const String &p_str) {
	CharString u8 = p_str.utf8();
	int n = MultiByteToWideChar(CP_UTF8, 0, u8.get_data(), (int)u8.length(), nullptr, 0);
	std::wstring w;
	w.resize(n > 0 ? n : 0);
	if (n > 0) {
		MultiByteToWideChar(CP_UTF8, 0, u8.get_data(), (int)u8.length(), &w[0], n);
	}
	return w;
}

inline String narrow(const wchar_t *p_w, int p_len = -1) {
	if (!p_w) {
		return String();
	}
	int len = p_len >= 0 ? p_len : (int)wcslen(p_w);
	if (len <= 0) {
		return String();
	}
	int n = WideCharToMultiByte(CP_UTF8, 0, p_w, len, nullptr, 0, nullptr, nullptr);
	if (n <= 0) {
		return String();
	}
	Vector<char> buf;
	buf.resize(n + 1);
	WideCharToMultiByte(CP_UTF8, 0, p_w, len, buf.ptrw(), n, nullptr, nullptr);
	buf.ptrw()[n] = 0;
	return String::utf8(buf.ptr(), n);
}

// Windows 系统目录（C:\Windows\System32）。
// 原程序取的是 "系统目录" 参与摘要；Godot 的 OS::get_system_dir() 需要 SystemDir 枚举，
// 且没有"系统目录"这一项，这里直接走 Win32，语义更贴近原实现。
inline String system_dir() {
	// [修正 2026-11-17] 原实现 `wchar_t buf[32768]` 在栈上占 64 KB 单帧。
	// 该函数被 machine_guid / system_volume_serial / device_tag 链调用，而这些调用
	// 会从 GDScript 线程（godot Thread，栈余量远小于主线程）深处进入；
	// 64 KB 单帧叠加引擎栈后会撞到 guard page，触发 CRT 的 __chkstk 失败路径
	// （BEX64 c0000409 / fastfail 2）。改为堆缓冲，语义完全不变。
	static const int kMax = 32767;
	Vector<wchar_t> buf;
	buf.resize(kMax + 1);
	if (buf.is_empty()) {
		return String();
	}
	UINT n = GetSystemDirectoryW(buf.ptrw(), (UINT)kMax);
	if (n == 0 || n >= (UINT)kMax) {
		return String();
	}
	return narrow(buf.ptr(), (int)n);
}

// -----------------------------------------------------------------------------
// 注册表（全部 HKCU/HKLM + RegOpenKeyExW 族，与 0x340Fxxx 段一致）
// -----------------------------------------------------------------------------
inline bool reg_read_string(HKEY p_root, const String &p_path, const String &p_name, String &r_out) {
	HKEY hk = nullptr;
	std::wstring path = wide(p_path);
	if (RegOpenKeyExW(p_root, path.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) {
		return false;
	}
	std::wstring name = wide(p_name);
	// [修正 2026-11-17] 原实现是栈上 wchar_t buf[1024] + `buf[cb/sizeof(wchar_t)] = 0`，
	// 一旦 API 在成功路径上把 cb 写到 sizeof(buf) 边界，末尾写 0 就越界 2 字节；
	// 同时 2 KB 栈帧在 GDScript 线程深处也有风险。改堆缓冲 + 显式上限校验。
	static const DWORD kCharCap = 1024;
	Vector<wchar_t> buf;
	buf.resize((int)kCharCap);
	if (buf.is_empty()) {
		RegCloseKey(hk);
		return false;
	}
	DWORD cb = (DWORD)(kCharCap * sizeof(wchar_t) - sizeof(wchar_t));
	DWORD type = 0;
	LONG rc = RegQueryValueExW(hk, name.empty() ? nullptr : name.c_str(), nullptr, &type, (LPBYTE)buf.ptrw(), &cb);
	RegCloseKey(hk);
	if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
		return false;
	}
	if (cb > kCharCap * sizeof(wchar_t)) {
		return false;
	}
	const DWORD chars = cb / sizeof(wchar_t);
	buf.ptrw()[chars] = 0;
	r_out = narrow(buf.ptr(), (int)chars);
	return true;
}

inline bool reg_write_string(HKEY p_root, const String &p_path, const String &p_name, const String &p_value) {
	HKEY hk = nullptr;
	std::wstring path = wide(p_path);
	if (RegCreateKeyExW(p_root, path.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hk, nullptr) != ERROR_SUCCESS) {
		return false;
	}
	std::wstring name = wide(p_name);
	std::wstring value = wide(p_value);
	DWORD cb = (DWORD)((value.size() + 1) * sizeof(wchar_t));
	LONG rc = RegSetValueExW(hk, name.empty() ? nullptr : name.c_str(), 0, REG_SZ, (const BYTE *)value.c_str(), cb);
	RegCloseKey(hk);
	return rc == ERROR_SUCCESS;
}

// 与 0x340EA60 的 REG_BINARY 分支一致：RegSetValueExW(REG_BINARY=3)
inline bool reg_write_binary(HKEY p_root, const String &p_path, const String &p_name,
		const Vector<uint8_t> &p_data) {
	HKEY hk = nullptr;
	std::wstring path = wide(p_path);
	if (RegCreateKeyExW(p_root, path.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &hk, nullptr) != ERROR_SUCCESS) {
		return false;
	}
	std::wstring name = wide(p_name);
	LONG rc = RegSetValueExW(hk, name.empty() ? nullptr : name.c_str(), 0, REG_BINARY /* = 3 */,
			(const BYTE *)p_data.ptr(), (DWORD)p_data.size());
	RegCloseKey(hk);
	return rc == ERROR_SUCCESS;
}

// 0x340ECE0 的取参形态：REG_BINARY / REG_SZ 都接，统一成字节
inline bool reg_read_binary(HKEY p_root, const String &p_path, const String &p_name,
		Vector<uint8_t> &r_out) {
	HKEY hk = nullptr;
	std::wstring path = wide(p_path);
	if (RegOpenKeyExW(p_root, path.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) {
		return false;
	}
	std::wstring name = wide(p_name);
	DWORD cb = 0;
	DWORD type = 0;
	LONG rc = RegQueryValueExW(hk, name.empty() ? nullptr : name.c_str(), nullptr, &type, nullptr, &cb);
	if (rc != ERROR_SUCCESS || cb == 0) {
		RegCloseKey(hk);
		return false;
	}
	r_out.resize((int)cb);
	rc = RegQueryValueExW(hk, name.empty() ? nullptr : name.c_str(), nullptr, &type,
			(LPBYTE)r_out.ptrw(), &cb);
	RegCloseKey(hk);
	if (rc != ERROR_SUCCESS) {
		r_out.clear();
		return false;
	}
	if (type == REG_SZ || type == REG_EXPAND_SZ) {
		// UTF-16 → UTF-8
		std::wstring w((const wchar_t *)r_out.ptr(), (size_t)cb / sizeof(wchar_t));
		while (!w.empty() && w.back() == 0) {
			w.pop_back();
		}
		String s = narrow(w.c_str(), (int)w.size());
		Vector<uint8_t> u8;
		u8.resize(s.length());
		memcpy(u8.ptrw(), s.utf8().get_data(), (size_t)s.length());
		r_out = u8;
	}
	r_out.resize((int)cb);
	return true;
}

// 与 0x340F0F0 完全一致的形状：开键成功 + 删值成功 ⇒ true
inline bool reg_delete_value(HKEY p_root, const String &p_path, const String &p_value) {
	HKEY hk = nullptr;
	std::wstring path = wide(p_path);
	if (RegOpenKeyExW(p_root, path.c_str(), 0, KEY_SET_VALUE /* = 2 */, &hk) != ERROR_SUCCESS) {
		return false;
	}
	std::wstring value = wide(p_value);
	LONG rc = RegDeleteValueW(hk, value.empty() ? nullptr : value.c_str());
	RegCloseKey(hk);
	return rc == ERROR_SUCCESS;
}
#endif

// -----------------------------------------------------------------------------
// base64（走引擎自带的 Marshalls，避免自带实现）
// -----------------------------------------------------------------------------
inline String b64_encode(const Vector<uint8_t> &p_data) {
	CoreBind::Marshalls *m = CoreBind::Marshalls::get_singleton();
	if (!m) {
		return String();
	}
	return m->raw_to_base64(p_data);
}

inline Vector<uint8_t> b64_decode(const String &p_text) {
	CoreBind::Marshalls *m = CoreBind::Marshalls::get_singleton();
	if (!m) {
		return Vector<uint8_t>();
	}
	return m->base64_to_raw(p_text.strip_edges());
}

} // namespace util
} // namespace xiewa
