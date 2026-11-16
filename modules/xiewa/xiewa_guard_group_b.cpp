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
// =============================================================================
String XiewaGuard::device_wrap2(const String &in) {
	if (gate()) {
		return String();
	}
#ifdef WINDOWS_ENABLED
	CharString u8 = in.utf8();
	int n = u8.length();
	Vector<uint8_t> mixed;
	mixed.resize(n);
	uint8_t *mw = mixed.ptrw();
	uint8_t ks[32];
	keystream2(device_tag(), ks);
	for (int i = 0; i < n; i++) {
		mw[i] = (uint8_t)(u8.get_data()[i] ^ ks[i % 32]);
	}
	Vector<uint8_t> cipher;
	if (!dpapi_protect(mixed, cipher)) {
		return String();
	}
	return String("XW2:") + util::b64_encode(cipher);
#else
	return String();
#endif
}

String XiewaGuard::device_unwrap2(const String &in) {
	if (gate()) {
		return String();
	}
#ifdef WINDOWS_ENABLED
	if (!in.begins_with("XW2:")) {
		return String();
	}
	Vector<uint8_t> cipher = util::b64_decode(in.substr(4));
	if (cipher.size() == 0) {
		return String();
	}
	Vector<uint8_t> mixed;
	if (!dpapi_unprotect(cipher, mixed)) {
		return String();
	}
	uint8_t ks[32];
	keystream2(device_tag(), ks);
	Vector<uint8_t> plain;
	plain.resize(mixed.size());
	uint8_t *p = plain.ptrw();
	for (int i = 0; i < mixed.size(); i++) {
		p[i] = (uint8_t)(mixed[i] ^ ks[i % 32]);
	}
	return String::utf8((const char *)plain.ptr(), plain.size());
#else
	return String();
#endif
}

Variant XiewaGuard::device_wrap_m2(const String &in) {
	if (gate()) {
		return Variant();
	}
	Dictionary d;
	d["v"] = 2;
	d["tag"] = device_tag().substr(0, 16);
	d["data"] = device_wrap2(in);
	d["dpapi"] = true;
	return d;
}

Variant XiewaGuard::device_unwrap_m2(const Variant &in) {
	if (gate()) {
		return Variant();
	}
	if (in.get_type() == Variant::STRING) {
		String s = in;
		return device_unwrap2(s);
	}
	if (in.get_type() == Variant::DICTIONARY) {
		Dictionary d = in;
		if (!d.has("data")) {
			return Variant();
		}
		return device_unwrap2((String)d["data"]);
	}
	return Variant();
}

// =============================================================================
//  derive2（0x38F2510）：三段 SHA-256 派生，标签 xw2-derive
// =============================================================================
String XiewaGuard::derive2(const String &in) {
	if (gate()) {
		return String();
	}
	uint8_t cur[32];
	String seed = String(kTagDerive) + "|" + in + "|" + String(kTagOmbrel);
	CharString u8 = seed.utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), cur);
	for (int round = 0; round < 3; round++) {
		uint8_t next[32];
		util::sha256(cur, 32, next);
		memcpy(cur, next, 32);
	}
	return util::to_hex32(cur);
}

// =============================================================================
//  sign2（0x38F2050）：HMAC + "save5…" 标签判定 + 时间窗
// =============================================================================
String XiewaGuard::sign2(const String &in) {
	if (gate()) {
		return String();
	}
	String key = pepper() + "|" + String(kTagDpapi2);
	// 存档类载荷带 "save5" 前缀时加标签，避免与普通载荷同签名
	String body = in.begins_with("save5") ? (in + "|save") : in;
	uint8_t mac[32];
	util::hmac_sha256(key, body, mac);
	return String("XWS2:") + util::to_hex32(mac);
}

// =============================================================================
//  verify2（0x38F2300）：解析 + base64 + SHA-256 比对（不是 RSA）
// =============================================================================
Variant XiewaGuard::verify2(const Variant &in) {
	Dictionary out;
	out["ok"] = false;
	out["err"] = String("format");

	String sig;
	String body;
	if (in.get_type() == Variant::DICTIONARY) {
		Dictionary d = in;
		if (!d.has("sig") || !d.has("body")) {
			return out;
		}
		sig = d["sig"];
		body = d["body"];
	} else if (in.get_type() == Variant::STRING) {
		String s = in;
		int bar = s.rfind("|");
		if (bar <= 0) {
			return out;
		}
		body = s.substr(0, bar);
		sig = s.substr(bar + 1);
	} else {
		return out;
	}

	String expect = sign2(body);
	if (!util::ct_equal(expect, sig)) {
		out["err"] = String("sig");
		return out;
	}
	out["ok"] = true;
	out["err"] = String();
	return out;
}

// =============================================================================
//  sign_blocked（0x38F2460）：三块 —— 双标志 / 状态门 / 时间窗 + 副本扫描
// =============================================================================
bool XiewaGuard::sign_blocked() {
	// ① 双标志
	if (g_block_a != 0 || g_block_b != 0) {
		return true;
	}
	// ② 状态门（0x560AAF4 的位运算）
	uint64_t w = g_flag_w;
	uint8_t d = (uint8_t)(w & 1);
	uint32_t n = (w & 0xE) ? (uint32_t)d + 2 : (uint32_t)d;
	if (n != 0) {
		g_block_a |= (int)n;
		return true;
	}
	// ③ 启动后 0x7D0 毫秒内的调用一律拦（防注入时序）
	if (g_first_tick == 0) {
		g_first_tick = OS::get_singleton()->get_ticks_msec();
		return true;
	}
	if (OS::get_singleton()->get_ticks_msec() - g_first_tick < 0x7D0) {
		return true;
	}
	// ④ 副本扫描：同名 exe 出现在系统目录（原程序自带探测器）
#ifdef WINDOWS_ENABLED
	String self = OS::get_singleton()->get_executable_path();
	String base = self.get_file();
	if (self.find("\\Windows\\") >= 0 || self.find("\\Temp\\") >= 0) {
		return true;
	}
	(void)base;
#endif
	return false;
}

// =============================================================================
//  test_block（0x38F8790）：副本指纹测试，返回诊断字典
// =============================================================================
Variant XiewaGuard::test_block(const Variant &in) {
	Dictionary out;
	out["blocked"] = sign_blocked();
	out["flags_a"] = g_block_a;
	out["flags_b"] = g_block_b;
	out["flag_w"] = (int64_t)g_flag_w;
	out["exe"] = OS::get_singleton()->get_executable_path().get_file();

	if (in.get_type() == Variant::STRING) {
		String probe = in;
		uint8_t d[32];
		CharString u8 = probe.utf8();
		util::sha256(u8.get_data(), (size_t)u8.length(), d);
		out["probe"] = probe;
		out["probe_hash"] = util::to_hex32(d);
	}
	return out;
}

// =============================================================================
//  editor_check / editor_cleanup（0x38F2DB0 / 0x38F3250）
// =============================================================================
Variant XiewaGuard::editor_check(const Variant &v) {
	Dictionary out;
	out["editor"] = OS::get_singleton()->has_feature("editor");
	out["debug"] = OS::get_singleton()->has_feature("debug");
	out["template"] = is_release_template();
	out["blocked"] = sign_blocked();
	if (v.get_type() == Variant::DICTIONARY) {
		Dictionary d = v;
		if (d.has("strict")) {
			out["strict"] = d["strict"];
		}
	}
	return out;
}

Variant XiewaGuard::editor_cleanup(const Variant &v) {
	Dictionary out;
	out["removed"] = 0;
	out["ok"] = true;

	String dir = String("user://") + vendor().to_lower() + "_" + cache_dir();
	Ref<DirAccess> da = DirAccess::open(dir);
	if (da.is_null()) {
		out["ok"] = false;
		out["err"] = String("container");
		return out;
	}
	da->list_dir_begin();
	int removed = 0;
	String f = da->get_next();
	while (!f.is_empty()) {
		if (!da->current_is_dir() && f != "." && f != "..") {
			if (DirAccess::remove_absolute(dir.path_join(f)) == OK) {
				removed++;
			}
		}
		f = da->get_next();
	}
	da->list_dir_end();

	out["removed"] = removed;
	if (v.get_type() == Variant::DICTIONARY) {
		Dictionary d = v;
		if (d.has("keep") && (bool)d["keep"]) {
			out["dir"] = dir;
		}
	}
	return out;
}

// =============================================================================
//  name2（0x38F36F0）：通道名规范化
// =============================================================================
String XiewaGuard::name2(const String &in) {
	if (gate()) {
		return String();
	}
	String s = in.strip_edges().to_lower();
	if (s.is_empty()) {
		return String();
	}
	// 已知通道固定映射，未知通道走 "xw2-" + 摘要前 12 位
	if (s == "save" || s == "save5") {
		return String("xiewa-save2");
	}
	if (s == "device" || s == "machine") {
		return String("xiewa-machine2");
	}
	if (s == "lic" || s == "license") {
		return String("xiewa-license2");
	}
	uint8_t d[32];
	CharString u8 = s.utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), d);
	return String("xw2-") + util::to_hex(d, 16).substr(0, 12);
}

} // namespace xiewa
