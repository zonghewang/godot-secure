// =============================================================================
//  XiewaGuard.cpp —— 组A 21 条的真实实现
//
//  覆盖 0x340C600 批里的全部方法（含 5 个常量方法），每条注明实现 RVA。
//  依据：_fixA.txt / _impl_all.asm / _reg_region.asm 的 IAT 与串注释。
//
//  标 [确证]：反汇编直接可见（调用哪个 API、哪个常量、哪个范围检查）
//  标 [推定]：形状已知、细节未逐字节展开，已按最合理语义落地，不留空实现
// =============================================================================

#include "xiewa_guard.h"
#include "xiewa_guard2d.h"
#include "xiewa_util.h"

#include "core/io/dir_access.h"
#include "core/io/file_access.h"
#include "core/os/os.h"
#include "core/variant/array.h"
#include "core/variant/dictionary.h"

#ifdef WINDOWS_ENABLED
#include <windows.h>
#endif

namespace xiewa {

namespace {

// 运行期配置（0x38EA8E0 解析出来的那一组键）
struct RuntimeState {
	bool configured = false;
	int scan_budget_ms = 1500;
	int max_handles = 512;
	int max_processes = 1024;
	int max_modules = 1024;
	int max_candidates = 32;
	int chunk_bytes = 0x10000;
	String schema;
	Dictionary baseline;
	Array known_modules;

	// 扫描运行态
	bool have_startup = false;
	uint8_t startup_digest[32] = { 0 };
	int consecutive_mismatches = 0;
	bool confirmed_mismatch = false;
};

RuntimeState g_rt;
HANDLE g_instance_mutex = nullptr;
Dictionary g_last_scan;

inline int clamp_key(const Dictionary &p_cfg, const char *p_key, int p_lo, int p_hi, int p_default) {
	if (!p_cfg.has(p_key)) {
		return p_default;
	}
	int64_t v = p_cfg[p_key];
	if (v < p_lo) {
		return p_lo;
	}
	if (v > p_hi) {
		return p_hi;
	}
	return (int)v;
}

#ifdef WINDOWS_ENABLED
// 第一族异或掩码（表 A@0x50A3100 / B@0x50A3120 实算值）
const uint8_t kMask1[32] = {
	0x14, 0xAC, 0xF1, 0x4B, 0x1A, 0x59, 0xA4, 0x1E,
	0x09, 0x16, 0xD6, 0xBD, 0x3D, 0x25, 0xF1, 0xF6,
	0xD6, 0xB2, 0x1E, 0xA8, 0x77, 0x15, 0xCF, 0x6F,
	0x28, 0xB6, 0xA1, 0x80, 0x4E, 0xE2, 0x4C, 0x0F,
};

// 用设备标签把固定掩码搅成每机不同的 keystream（同机可逆）
void keystream1(const String &p_tag, uint8_t r_out[32]) {
	uint8_t seed[32];
	util::sha256(kMask1, 32, seed);
	uint8_t tag_digest[32];
	CharString t = p_tag.utf8();
	util::sha256(t.get_data(), (size_t)t.length(), tag_digest);
	for (int i = 0; i < 32; i++) {
		r_out[i] = (uint8_t)(seed[i] ^ tag_digest[i]);
	}
}

// SMBIOS type 1 的 UUID（0x38F7230 里 GetSystemFirmwareTable(0x5253424D,'RSMB') 那段）
String smbios_uuid() {
	DWORD size = GetSystemFirmwareTable(0x5253424Du, 0u, nullptr, 0);
	if (size < 16) {
		return String();
	}
	Vector<uint8_t> buf;
	buf.resize((int)size);
	if (GetSystemFirmwareTable(0x5253424Du, 0u, buf.ptrw(), size) != size) {
		return String();
	}
	const uint8_t *p = buf.ptr();
	uint32_t pos = 8; // 'RSMB' + Major(1) + Minor(1) + 表长(2)
	while (pos + 4 <= size) {
		uint8_t type = p[pos];
		uint8_t len = p[pos + 1];
		if (len < 4) {
			break;
		}
		if (type == 1 && len >= 0x19) {
			uint8_t uuid[16];
			memcpy(uuid, p + pos + 8, 16);
			String s = util::to_hex(uuid, 16);
			if (s.length() == 32) {
				return s.substr(0, 8) + "-" + s.substr(8, 4) + "-" + s.substr(12, 4) + "-" +
						s.substr(16, 4) + "-" + s.substr(20, 12);
			}
			return s;
		}
		pos += len;
		while (pos + 1 < size && !(p[pos] == 0 && p[pos + 1] == 0)) {
			pos++;
		}
		pos += 2;
	}
	return String();
}

String machine_guid() {
	String v;
	if (util::reg_read_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", v)) {
		return v;
	}
	return String();
}

String system_volume_serial() {
	wchar_t root[4] = { L'C', L':', L'\\', 0 };
	String sys = util::system_dir();
	if (sys.length() >= 2 && ((sys[0] >= 'A' && sys[0] <= 'Z') || (sys[0] >= 'a' && sys[0] <= 'z'))) {
		root[0] = (wchar_t)sys[0];
	}
	DWORD serial = 0;
	wchar_t label[256], fs[256];
	if (!GetVolumeInformationW(root, label, 256, &serial, nullptr, nullptr, fs, 256)) {
		return String();
	}
	return String::num_uint64(serial);
}
#endif

} // namespace

// =============================================================================
//  配置 / 扫描
// =============================================================================

// 0x38EA8E0（4184 B）：schema / scan_budget_ms / max_handles / max_processes /
// max_modules / max_candidates / d4_chunk_bytes / integrity_baseline / known_modules
void XiewaGuard::configure_runtime_detection(const Variant &cfg) {
	if (cfg.get_type() != Variant::DICTIONARY) {
		return;
	}
	Dictionary d = cfg;

	if (d.has("schema")) {
		String s = d["schema"];
		if (s.length() > 0) {
			g_rt.schema = s;
		}
	}
	// 上下限是实测立即数
	g_rt.scan_budget_ms = clamp_key(d, "scan_budget_ms", 100, 5000, g_rt.scan_budget_ms);
	g_rt.max_handles = clamp_key(d, "max_handles", 1, 0x10000, g_rt.max_handles);
	g_rt.max_processes = clamp_key(d, "max_processes", 1, 0x1000, g_rt.max_processes);
	g_rt.max_modules = clamp_key(d, "max_modules", 1, 0x400, g_rt.max_modules);
	g_rt.max_candidates = clamp_key(d, "max_candidates", 1, 0x20, g_rt.max_candidates);
	g_rt.chunk_bytes = clamp_key(d, "d4_chunk_bytes", 8, 0x10000, g_rt.chunk_bytes);

	// integrity_baseline：非空才替换（对应 `[rax+0x34] != 0` 才用）
	if (d.has("integrity_baseline")) {
		Variant b = d["integrity_baseline"];
		if (b.get_type() == Variant::DICTIONARY) {
			Dictionary bd = b;
			if (!bd.is_empty()) {
				g_rt.baseline = bd;
			}
		}
	}
	if (d.has("known_modules")) {
		Variant m = d["known_modules"];
		if (m.get_type() == Variant::ARRAY) {
			g_rt.known_modules = m;
		}
	}

	g_rt.configured = true;
	g_rt.have_startup = false;
	g_rt.consecutive_mismatches = 0;
	g_rt.confirmed_mismatch = false;
}

// 0x38ECA00：用已配置的基线跑一次自校验，产出报告字典
Variant XiewaGuard::scan_runtime_detection() {
	Dictionary out;
	out["status"] = String("unavailable");
	out["confirmed_mismatch"] = false;
	out["changed_since_startup"] = false;
	out["consecutive_mismatches"] = g_rt.consecutive_mismatches;

	if (!g_rt.configured || g_rt.baseline.is_empty()) {
		out["err"] = String("_baseline_invalid");
		g_last_scan = out;
		return out;
	}

	xiewa_guard2d::Meta meta;
	String err;
	if (!xiewa_guard2d::impl::meta_from_dictionary(g_rt.baseline, meta, err)) {
		out["err"] = err;
		g_last_scan = out;
		return out;
	}

	xiewa_guard2d::CurrentProcessReader reader;
	xiewa_guard2d::ImageState state;
	uint64_t t0 = OS::get_singleton()->get_ticks_usec();
	bool ok = xiewa_guard2d::impl::verify(&state, &reader, meta, err);
	uint64_t spent_us = OS::get_singleton()->get_ticks_usec() - t0;

	bool have_digest = false;
	for (int i = 0; i < 32; i++) {
		if (state.digest[i] != 0) {
			have_digest = true;
			break;
		}
	}
	String observed = have_digest ? util::to_hex32(state.digest) : String();

	out["observed_sha256"] = observed;
	out["bytes_hashed"] = (int64_t)state.info.text_size;
	out["last_us"] = (int64_t)spent_us;
	out["integrity"] = ok;

	if (!g_rt.have_startup && ok) {
		memcpy(g_rt.startup_digest, state.digest, 32);
		g_rt.have_startup = true;
	}
	out["startup_sha256"] = g_rt.have_startup ? util::to_hex32(g_rt.startup_digest) : String();

	if (ok) {
		g_rt.consecutive_mismatches = 0;
		g_rt.confirmed_mismatch = false;
		out["status"] = String("match");
	} else {
		g_rt.consecutive_mismatches++;
		// [推定] 连续 3 次不一致才升级（阈值在 0x38ECA00 尾部按连续计数判定）
		if (g_rt.consecutive_mismatches >= 3) {
			g_rt.confirmed_mismatch = true;
		}
		out["status"] = have_digest ? String("mismatch") : String("unavailable");
		out["err"] = err;
	}

	bool changed = g_rt.have_startup && have_digest &&
			!util::ct_equal(g_rt.startup_digest, state.digest, 32);
	out["changed_since_startup"] = changed;
	out["consecutive_mismatches"] = g_rt.consecutive_mismatches;
	out["confirmed_mismatch"] = g_rt.confirmed_mismatch;
	out["scan_budget_ms"] = g_rt.scan_budget_ms;

	g_last_scan = out;
	return out;
}

// =============================================================================
//  音频输出标识（0x38F04F0）
//  实测走注册表枚举 + 拼接 + 摘要；这里枚举 MMDevices\Audio\Render 的端点 GUID
// =============================================================================
String XiewaGuard::audio_output_identity() {
#ifdef WINDOWS_ENABLED
	String acc;
	HKEY hk = nullptr;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
				L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Render",
				0, KEY_READ, &hk) == ERROR_SUCCESS) {
		for (DWORD i = 0; i < 4096; i++) {
			wchar_t name[256];
			DWORD cch = 256;
			if (RegEnumKeyExW(hk, i, name, &cch, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
				break;
			}
			acc += util::narrow(name, (int)cch) + "|";
			if (acc.length() > 8192) {
				break;
			}
		}
		RegCloseKey(hk);
	}
	if (acc.is_empty()) {
		return String("unavailable");
	}
	uint8_t d[32];
	CharString u8 = acc.utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), d);
	return util::to_hex32(d);
#else
	return String("unavailable");
#endif
}

// =============================================================================
//  设备封装 / 解封（0x340D7E0 / 0x340DA40 / 0x340DCB0 / 0x340DED0）
// =============================================================================
String XiewaGuard::device_wrap(const String &in) {
#ifdef WINDOWS_ENABLED
	CharString u8 = in.utf8();
	int n = u8.length();
	Vector<uint8_t> out;
	out.resize(n);
	uint8_t *w = out.ptrw();
	uint8_t ks[32];
	keystream1(device_tag(), ks);
	for (int i = 0; i < n; i++) {
		w[i] = (uint8_t)(u8.get_data()[i] ^ ks[i % 32]);
	}
	return String("XW1:") + util::b64_encode(out);
#else
	return in;
#endif
}

String XiewaGuard::device_unwrap(const String &in) {
#ifdef WINDOWS_ENABLED
	if (!in.begins_with("XW1:")) {
		return String();
	}
	Vector<uint8_t> raw = util::b64_decode(in.substr(4));
	if (raw.size() == 0) {
		return String();
	}
	uint8_t ks[32];
	keystream1(device_tag(), ks);
	Vector<uint8_t> plain;
	plain.resize(raw.size());
	uint8_t *w = plain.ptrw();
	for (int i = 0; i < raw.size(); i++) {
		w[i] = (uint8_t)(raw[i] ^ ks[i % 32]);
	}
	return String::utf8((const char *)plain.ptr(), plain.size());
#else
	return in;
#endif
}

// 带元信息的封装：data 密文 / tag 设备标签前缀 / v 版本
Variant XiewaGuard::device_wrap_m(const String &in) {
	Dictionary d;
	d["v"] = 1;
	d["tag"] = device_tag().substr(0, 16);
	d["data"] = device_wrap(in);
	return d;
}

// 接受 Dictionary 或 String 两种输入
Variant XiewaGuard::device_unwrap_m(const Variant &in) {
	if (in.get_type() == Variant::STRING) {
		String s = in;
		return device_unwrap(s);
	}
	if (in.get_type() == Variant::DICTIONARY) {
		Dictionary d = in;
		if (!d.has("data")) {
			return Variant();
		}
		return device_unwrap((String)d["data"]);
	}
	return Variant();
}

// =============================================================================
//  设备标签 / pepper（0x340E0F0 1938 B / 0x340E890 461 B）
//  实测两者长度差 4 倍，不是同一个函数
// =============================================================================
String XiewaGuard::device_tag() {
#ifdef WINDOWS_ENABLED
	String acc;
	acc += system_volume_serial() + "|";
	acc += machine_guid() + "|";
	acc += String::num_int64(OS::get_singleton()->get_processor_count()) + "|";
	Dictionary mem = OS::get_singleton()->get_memory_info();
	acc += String::num_uint64((uint64_t)(int64_t)mem.get("physical", 0)) + "|";
	acc += util::system_dir() + "|";
	acc += smbios_uuid();

	uint8_t d[32];
	CharString u8 = acc.utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), d);
	return util::to_hex32(d);
#else
	return String("unavailable");
#endif
}

String XiewaGuard::pepper() {
	String seed = device_tag() + "|" + vendor() + "|ombrel-pepper";
	uint8_t d[32];
	CharString u8 = seed.utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), d);
	return util::to_hex32(d);
}

// =============================================================================
//  注册表三件（0x340EA60 / 0x340ECE0 / 0x340F0F0）
// =============================================================================
bool XiewaGuard::reg_write(const String &name, const String &value) {
#ifdef WINDOWS_ENABLED
	String path = "Software\\" + vendor() + "\\" + reg_subkey();
	return util::reg_write_string(HKEY_CURRENT_USER, path, name, value);
#else
	(void)name;
	(void)value;
	return false;
#endif
}

String XiewaGuard::reg_read(const String &name) {
#ifdef WINDOWS_ENABLED
	String path = "Software\\" + vendor() + "\\" + reg_subkey();
	String v;
	if (util::reg_read_string(HKEY_CURRENT_USER, path, name, v)) {
		return v;
	}
	return String();
#else
	(void)name;
	return String();
#endif
}

// 0x340F0F0（559 B）：HKCU + KEY_SET_VALUE(2) + RegDeleteValueW；
// "Software\" + subkey 为路径，value 为值名，两步都成功才 true
bool XiewaGuard::reg_erase(const String &subkey, const String &value) {
#ifdef WINDOWS_ENABLED
	String path = "Software\\" + subkey;
	return util::reg_delete_value(HKEY_CURRENT_USER, path, value);
#else
	(void)subkey;
	(void)value;
	return false;
#endif
}

// =============================================================================
//  文件落盘两件（0x340F320 / 0x340F400）
// =============================================================================
bool XiewaGuard::flush_file(const String &path) {
	Ref<FileAccess> fa = FileAccess::open(path, FileAccess::READ_WRITE);
	if (fa.is_null()) {
		return false;
	}
	fa->flush();
	return true;
}

bool XiewaGuard::move_file_durable(const String &from, const String &to) {
#ifdef WINDOWS_ENABLED
	std::wstring wf = util::wide(from);
	std::wstring wt = util::wide(to);
	// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
	if (MoveFileExW(wf.c_str(), wt.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		return true;
	}
	// 跨卷失败时退化：拷贝 + flush + 删源（仍然是持久落盘）
	Ref<FileAccess> src = FileAccess::open(from, FileAccess::READ);
	if (src.is_null()) {
		return false;
	}
	Ref<FileAccess> dst = FileAccess::open(to, FileAccess::WRITE);
	if (dst.is_null()) {
		return false;
	}
	Vector<uint8_t> buf;
	buf.resize(0x10000);
	int64_t left = (int64_t)src->get_length();
	while (left > 0) {
		int64_t take = left > 0x10000 ? 0x10000 : left;
		uint64_t got = src->get_buffer(buf.ptrw(), (uint64_t)take);
		if (got == 0) {
			return false;
		}
		dst->store_buffer(buf.ptr(), (int64_t)got);
		left -= (int64_t)got;
	}
	dst->flush();
	dst->close();
	src->close();
	return DirAccess::remove_absolute(from) == OK;
#else
	(void)from;
	(void)to;
	return false;
#endif
}

// =============================================================================
//  单实例（0x340F520）：CreateMutexW 的第三参就是 mutex_name() 的固定 GUID
// =============================================================================
bool XiewaGuard::single_instance_acquire() {
#ifdef WINDOWS_ENABLED
	if (g_instance_mutex != nullptr) {
		return true;
	}
	std::wstring name = util::wide(mutex_name());
	HANDLE h = CreateMutexW(nullptr, TRUE, name.c_str());
	if (h == nullptr) {
		return false;
	}
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		ReleaseMutex(h);
		CloseHandle(h);
		return false;
	}
	g_instance_mutex = h;
	return true;
#else
	return true;
#endif
}

// =============================================================================
//  五常量（0x340F590 / 0x340F5A0 / 0x340F5E0 / 0x340F620 / 0x340F660 / 0x340F6A0）
// =============================================================================
bool XiewaGuard::is_release_template() {
	return true; // `mov al,1; ret`
}

String XiewaGuard::flavor() {
	return String("release");
}

String XiewaGuard::vendor() {
	return String("Ombrel");
}

String XiewaGuard::reg_subkey() {
	return String("Cache");
}

String XiewaGuard::cache_dir() {
	return String("cache");
}

String XiewaGuard::mutex_name() {
	return String("Local\\Ombrel.{18657BB7-EFAC-44EA-8C0D-5D6F3E7454EB}");
}

} // namespace xiewa
