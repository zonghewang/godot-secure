// =============================================================================
//  xiewa_util.h —— 模块内部公共工具（全部 inline，无单独编译单元）
//
//  提供：SHA-256 / HMAC-SHA-256 / hex / 宽字符转换 / 注册表读写 / 常量时间比较
//  只依赖 Win32 + Godot core，不引入外部库。
// =============================================================================

#pragma once

#include "core/core_bind.h" // Marshalls
#include "core/string/ustring.h"
#include "core/templates/vector.h"

#include <stdint.h>
#include <string.h>
#include <string>

#ifdef WINDOWS_ENABLED
#include <windows.h>
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
	wchar_t buf[32768];
	UINT n = GetSystemDirectoryW(buf, 32767);
	if (n == 0 || n >= 32767) {
		return String();
	}
	return narrow(buf, (int)n);
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
	wchar_t buf[1024];
	DWORD cb = sizeof(buf) - sizeof(wchar_t);
	DWORD type = 0;
	LONG rc = RegQueryValueExW(hk, name.empty() ? nullptr : name.c_str(), nullptr, &type, (LPBYTE)buf, &cb);
	RegCloseKey(hk);
	if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
		return false;
	}
	buf[cb / sizeof(wchar_t)] = 0;
	r_out = narrow(buf);
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
