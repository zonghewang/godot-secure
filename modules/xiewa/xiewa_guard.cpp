// =============================================================================
//  xiewa_guard.cpp —— 组A（21 个方法）的实现
//
//  这一组是机器侧的基础能力：运行时检测、设备指纹、设备加解密、
//  注册表读写、文件落盘、单实例互斥、缓存目录。
//
//  实现依据原程序的导入表与字符串常量：
//    [确证] 反汇编里直接看得见（调了哪个 API、哪个常量、哪个范围检查）
//    [推定] 形状已知、细节未逐字节展开，按最合理语义补全（没有留空实现）
// =============================================================================

#include "xiewa_guard.h"
#include "xiewa_guard2d.h"
#include "xiewa_util.h"

#include "core/io/dir_access.h"
#include "core/io/file_access.h"
#include "core/math/math_funcs.h"
#include "core/os/os.h"
#include "core/variant/array.h"
#include "core/variant/dictionary.h"

#include <mutex>

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

	// d4（镜像完整性）的资格声明。pck 内
	// res://resources/安全/runtime_detection.json 实测写的是
	// "NOT_RUN_RECORD_ONLY"，且 数值守卫.gd 把
	// const D4_ENFORCEMENT_QUALIFIED := False 硬编码 —— 原版 d4 只记录、不执行。
	String d4_qualification = "NOT_RUN_RECORD_ONLY";
};

RuntimeState g_rt;
HANDLE g_instance_mutex = nullptr;
Dictionary g_last_scan;

// [修正 2026-11-17] g_rt 会被两条线程触碰：
//   ① 主线程 _initialize → configure_runtime_detection()
//   ② 工具检测.gd::_scan 起的 Thread → scan_runtime_detection()
// 之前 scan 里还每次都调 configure_runtime_detection(opts)，等于在扫描线程里
// 反复改写同一个 RuntimeState（含 Dictionary baseline）并与主线程并发，
// 属于典型的数据竞态 —— 破坏 Variant/Dictionary 的引用计数与栈上对象，
// 正好对应 fastfail 2（栈 cookie 校验失败）。这里统一加锁，并保证
// scan 只读配置、不再重灌。
std::mutex &rt_lock() {
	static std::mutex m;
	return m;
}

// 进程启动标识：脚本侧契约要求 target_start 是「纯十进制、>0、长度 ≤ 20」，
// 且同一进程内必须恒定（用于判定目标进程是否被换掉）。
// 取内核记录的进程创建时间 FILETIME（100ns 精度，约 1.3e17，18 位）。
#ifdef WINDOWS_ENABLED
String process_start_token() {
	FILETIME ct, et, kt, ut;
	if (GetProcessTimes(GetCurrentProcess(), &ct, &et, &kt, &ut)) {
		const uint64_t v = ((uint64_t)ct.dwHighDateTime << 32) | (uint64_t)ct.dwLowDateTime;
		if (v > 0 && v < 10000000000000000000ull) {
			return String::num_uint64(v);
		}
	}
	return String("1");
}
#else
String process_start_token() {
	return String("1");
}
#endif

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
bool XiewaGuard::configure_runtime_detection(const Dictionary &cfg) {
	if (cfg.is_empty()) {
		return false;
	}
	std::lock_guard<std::mutex> lock(rt_lock());
	const Dictionary &d = cfg;

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
	// d4 资格：只有 ENFORCEMENT_QUALIFIED 才允许真跑镜像哈希
	if (d.has("d4_qualification")) {
		String q = d["d4_qualification"];
		if (!q.is_empty()) {
			g_rt.d4_qualification = q;
		}
	}

	g_rt.configured = true;
	g_rt.have_startup = false;
	g_rt.consecutive_mismatches = 0;
	g_rt.confirmed_mismatch = false;
	return true;
}

// 0x38ECA00：用已配置的基线跑一次自校验，产出报告字典
//
// [修正 2026-11-17] 返回值必须严格满足脚本侧契约
//   res://globals/native_scan_contract.gd::validate()：
//     schema:int==1 / target_pid:int / target_start:String(纯数字、>0、≤20 位) /
//     hits:Array≤128（每项 tool/evidence String、confirmed/attached bool）/
//     diagnostics:Array≤256 / integrity:Dictionary（state 属枚举） / complete:bool
//   旧实现返回 {status, confirmed_mismatch, changed_since_startup,
//   consecutive_mismatches, err}，且把 integrity 直接塞成 bool，
//   validate() 第一条 schema 就不满足，于是兜底成
//     {"diagnostics":["native_invalid_result"]}
//   —— 这就是日志里 ["native_invalid_result"] 的唯一产生点。
//   同时不再在 scan 里调 configure_runtime_detection：那是配置通道，
//   在扫描线程里每次重灌会把 have_startup / consecutive_mismatches 清零，
//   并与主线程并发改写同一个 RuntimeState。
Dictionary XiewaGuard::scan_runtime_detection(const Dictionary &opts) {
	Dictionary out;
	out["schema"] = 1;
	out["target_pid"] = (int)OS::get_singleton()->get_process_id();
	out["target_start"] = process_start_token();
	out["complete"] = true;
	out["hits"] = Array();

	Array diag;
	Dictionary integrity;
	integrity["state"] = String("not_requested");

	bool want_d4 = false;
	if (opts.has("d4")) {
		Variant v = opts["d4"];
		want_d4 = (v.get_type() == Variant::BOOL) ? (bool)v : bool((int64_t)v);
	}

	// 未要求 d4（镜像/模块校验）时，按契约给出 not_requested 的空报告。
	if (!want_d4) {
		out["diagnostics"] = diag;
		out["integrity"] = integrity;
		return out;
	}

	// [修正 2026-11-17] 按原版资格声明决定 d4 是否真的跑镜像哈希。
	// pck 里 runtime_detection.json 写的是 "NOT_RUN_RECORD_ONLY"，
	// 脚本侧 const D4_ENFORCEMENT_QUALIFIED := False —— 原版只记录、不执行。
	// 旧实现无条件在 Thread（实测栈仅 228 KB）里跑 68 MB .text 分块哈希，
	// 既与原始行为不符，也会把后台线程拉进一条很长的调用链。
	bool d4_enforce = false;
	{
		std::lock_guard<std::mutex> lock(rt_lock());
		d4_enforce = (g_rt.d4_qualification == String("ENFORCEMENT_QUALIFIED"));
	}
	if (!d4_enforce) {
		integrity["state"] = String("not_requested");
		diag.push_back(String("D4:NOT_RUN_RECORD_ONLY"));
		out["diagnostics"] = diag;
		out["integrity"] = integrity;
		return out;
	}

	Dictionary baseline;
	{
		std::lock_guard<std::mutex> lock(rt_lock());
		if (!g_rt.configured || g_rt.baseline.is_empty()) {
			integrity["state"] = String("unavailable");
			diag.push_back(String("_baseline_invalid"));
			out["diagnostics"] = diag;
			out["integrity"] = integrity;
			return out;
		}
		// 深拷贝：后面在扫描线程里读，主线程可能同时改配置
		baseline = g_rt.baseline.duplicate(true);
	}

	xiewa_guard2d::Meta meta;
	String err;
	if (!xiewa_guard2d::impl::meta_from_dictionary(baseline, meta, err)) {
		integrity["state"] = String("unavailable");
		diag.push_back(err.is_empty() ? String("_meta_invalid") : err.left(2048));
		out["diagnostics"] = diag;
		out["integrity"] = integrity;
		return out;
	}

	xiewa_guard2d::CurrentProcessReader reader;
	xiewa_guard2d::ImageState state;
	const uint64_t t0 = OS::get_singleton()->get_ticks_usec();
	const bool ok = xiewa_guard2d::impl::verify(&state, &reader, meta, err);
	const uint64_t spent_us = OS::get_singleton()->get_ticks_usec() - t0;

	bool have_digest = false;
	for (int i = 0; i < 32; i++) {
		if (state.digest[i] != 0) {
			have_digest = true;
			break;
		}
	}

	int consec = 0;
	bool confirmed = false;
	bool changed = false;
	{
		std::lock_guard<std::mutex> lock(rt_lock());
		if (!g_rt.have_startup && ok) {
			memcpy(g_rt.startup_digest, state.digest, 32);
			g_rt.have_startup = true;
		}
		changed = g_rt.have_startup && have_digest &&
				!util::ct_equal(g_rt.startup_digest, state.digest, 32);
		if (ok) {
			g_rt.consecutive_mismatches = 0;
			g_rt.confirmed_mismatch = false;
		} else {
			g_rt.consecutive_mismatches++;
			// [推定] 连续 3 次不一致才升级（阈值在 0x38ECA00 尾部按连续计数判定）
			if (g_rt.consecutive_mismatches >= 3) {
				g_rt.confirmed_mismatch = true;
			}
		}
		consec = g_rt.consecutive_mismatches;
		confirmed = g_rt.confirmed_mismatch;
	}

	if (ok) {
		integrity["state"] = String("match");
	} else {
		integrity["state"] = have_digest ? String("mismatch") : String("unavailable");
	}
	// 契约：confirmed_mismatch 为 true 时 state 必须就是 confirmed_mismatch，
	// 且 consecutive_mismatches ≥ 2（我们阈值是 3，天然满足）。
	if (confirmed && consec >= 2) {
		integrity["state"] = String("confirmed_mismatch");
		integrity["confirmed_mismatch"] = true;
	}
	integrity["changed_since_startup"] = changed;
	integrity["consecutive_mismatches"] = consec;

	if (!err.is_empty()) {
		diag.push_back(err.left(2048));
	}

	out["diagnostics"] = diag;
	out["integrity"] = integrity;

	// 排障用的详细报告（脚本不消费，仅保留给 native 侧诊断）
	Dictionary last;
	last["observed_sha256"] = have_digest ? util::to_hex32(state.digest) : String();
	last["bytes_hashed"] = (int64_t)state.info.text_size;
	last["last_us"] = (int64_t)spent_us;
	last["integrity"] = ok;
	last["state"] = integrity["state"];
	{
		std::lock_guard<std::mutex> lock(rt_lock());
		g_last_scan = last;
	}
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
//  原版 DPAPI 静态熵（v1 第一代 / v2 第二代），用于解原程序写下的旧数据
//  v1 熵：0x340D7E0 现场生成（T1@0x50A3100 / T2@0x50A3120 摊平），实算常量如下
//  v2 熵：由 sha256(exe .text) 经两段式 KDF 派生，实算常量如下（已解 Diao 老档验证）
// =============================================================================
#ifdef WINDOWS_ENABLED
static const uint8_t kEntropyGen1[32] = {
	0x14, 0xAC, 0xF1, 0x4B, 0x1A, 0x59, 0xA4, 0x1E,
	0x09, 0x16, 0xD6, 0xBD, 0x3D, 0x25, 0xF1, 0xF6,
	0x64, 0xB2, 0x1E, 0xA8, 0x77, 0x15, 0xCF, 0x6F,
	0x28, 0xB6, 0xA1, 0x80, 0x4E, 0xE2, 0x4C, 0x0F,
};
static const uint8_t kEntropyGen2[32] = {
	0x2C, 0x74, 0x0F, 0x13, 0x13, 0x81, 0xCB, 0xFB,
	0xAF, 0xBE, 0x83, 0x06, 0xC6, 0xCA, 0x29, 0x35,
	0x3D, 0x20, 0x9D, 0x97, 0x26, 0x9D, 0xEF, 0xF4,
	0x3B, 0x08, 0xD6, 0x71, 0x65, 0x43, 0xB3, 0x25,
};

static bool dpapi_unprotect_with_entropy(const PackedByteArray &p_in, const uint8_t *p_entropy,
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
	memcpy(r_out.ptrw(), out_blob.pbData, (size_t)out_blob.cbData);
	LocalFree(out_blob.pbData);
	return true;
}

// [修正 2026-11-18] 带静态熵的 DPAPI 封装：原版 v1 段（0x340D7E0 的 user 段）就是
//   直接 CryptProtectData(明文, desc="ombrel", entropy=kEntropyGen2)——
//   现场样本 aa329b93408291a9 / b299a8b3cb53c02b 的 user 段用 kEntropyGen2 可解，
//   解得 1676 B / 32 B 明文，首 u32 分别是 27（DICT）与裸密钥。
static bool dpapi_protect_with_entropy(const Vector<uint8_t> &p_in, const uint8_t *p_entropy,
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

// 读取官方设备种子（0x340E0F0 的输入侧实证）：
//   官方 device_tag(path) 先 FileAccess 打开 path 读全部字节，再走 device_unwrap
//   （= CryptUnprotectData + entropy = kEntropyGen1），解出内容长度必须恰好 32 字节，
//   否则视为无效。path 由脚本传 device_store_path()，即
//   %LOCALAPPDATA%\<vendor>\<cache_dir>\0.bin（现场 C:\Users\<u>\AppData\Local\Ombrel\cache\0.bin）。
//   实测该文件 274 B，用 kEntropyGen1 解出 32 B：50b1a9a7…677dc39f，与官方实现对齐。
static bool device_seed32(uint8_t r_out[32]) {
	String base = OS::get_singleton()->get_environment("LOCALAPPDATA");
	if (base.is_empty()) {
		return false;
	}
	String path = base.replace("\\", "/") + "/Ombrel/cache/0.bin";
	Ref<FileAccess> f = FileAccess::open(path, FileAccess::READ);
	if (f.is_null()) {
		return false;
	}
	PackedByteArray blob = f->get_buffer((int)f->get_length());
	f.unref();
	if (blob.size() == 0) {
		return false;
	}
	Vector<uint8_t> plain;
	if (!dpapi_unprotect_with_entropy(blob, kEntropyGen1, plain)) {
		return false;
	}
	if (plain.size() != 32) {
		return false;
	}
	memcpy(r_out, plain.ptr(), 32);
	return true;
}

// 带 LOCAL_MACHINE 语义的 DPAPI（官方 device_wrap_m 的 dwFlags = 5：
// CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE）
static bool dpapi_protect_machine(const Vector<uint8_t> &p_in, const uint8_t *p_entropy,
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

static bool dpapi_unprotect_machine(const Vector<uint8_t> &p_in, const uint8_t *p_entropy,
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
				CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &out_blob)) {
		return false;
	}
	r_out.resize((int)out_blob.cbData);
	memcpy(r_out.ptrw(), out_blob.pbData, (size_t)out_blob.cbData);
	LocalFree(out_blob.pbData);
	return true;
}
#endif

// =============================================================================
//  设备封装 / 解封（0x340D7E0 / 0x340DA40 / 0x340DCB0 / 0x340DED0）
//  [修正 2026-11-16] 载体改为 PackedByteArray（exe 类型表四条都是 [PBA, PBA]）
// =============================================================================
PackedByteArray XiewaGuard::device_wrap(const PackedByteArray &in) {
	PackedByteArray out;
#ifdef WINDOWS_ENABLED
	// [修正 2026-11-18 二次] 反汇编 0x340D7E0 逐指令实证：官方 device_wrap 就是一次
	//   CryptProtectData(
	//       pDataIn          = 输入整段 PackedByteArray,
	//       szDataDescr      = L"ombrel"，
	//       pOptionalEntropy = 32 B 常量（由 0x340D827/0x340D82E 指向的
	//                          .rdata 两表 0x50A3100 / 0x50A3120 现场摊平生成），
	//       pwszPrompt       = NULL, dwFlags = CRYPTPROTECT_UI_FORBIDDEN(1))
	//
	// 摊平公式（0x340D840..0x340D881，k = 0..15）：
	//   rax = 1 + 2k ; r8 = 0x12 + 0x1A*k ; dl = 0x3B + 0x76*k
	//   out[rax-1] = (B[((r8 - 0x0D) & 0x1F)] + dl + 0xC5) ^ A[rax-1]
	//   out[rax]   = (B[(r8 & 0x1E)]            + dl)        ^ A[rax]
	// 实算结果 = 14acf14b1a59a41e0916d6bd3d25f1f664b21ea87715cf6f28b6a1804ee24c0f，
	// 与 kEntropyGen1 完全一致（已用 1 组 Python 复算对齐）。
	//
	// 结论：v1 段既不做设备标签 keystream，也不产 XWD3 容器。
	//   XWD3 头由脚本层 守护.gd:device_wrap() 自己拼（8 字节头 + user 段 + machine 段），
	//   native 只负责段内那一次 DPAPI。上一版把容器塞进本函数会造成双重封装，
	//   官方版因此解不出我方写的值（现场 T4_MARKS_BROKEN 的直接成因）。
	Vector<uint8_t> plain;
	plain.resize(in.size());
	if (in.size() > 0) {
		memcpy(plain.ptrw(), in.ptr(), (size_t)in.size());
	}
	Vector<uint8_t> cipher;
	if (!dpapi_protect_with_entropy(plain, kEntropyGen1, cipher)) {
		return out;
	}
	out.resize((int)cipher.size());
	memcpy(out.ptrw(), cipher.ptr(), (size_t)cipher.size());
#else
	out = in;
#endif
	return out;
}

PackedByteArray XiewaGuard::device_unwrap(const PackedByteArray &in) {
	PackedByteArray out;
#ifdef WINDOWS_ENABLED
	// [修正 2026-11-18 二次] 官方 0x340DA40 与本函数逐指令对称：只做一次
	//   CryptUnprotectData(pDataIn, szDataDescr=NULL, pOptionalEntropy=kEntropyGen1,
	//                      NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN)
	// XWD3 容器由脚本层 守护.gd:device_unwrap_ex() 先按 magic 剥掉并分流到
	// device_unwrap2 / device_unwrap_m2，不会进到这里，所以这里不做容器解析。
	if (in.size() == 0) {
		return out;
	}
	Vector<uint8_t> cipher;
	cipher.resize(in.size());
	memcpy(cipher.ptrw(), in.ptr(), (size_t)in.size());
	Vector<uint8_t> plain;
	if (dpapi_unprotect_with_entropy(cipher, kEntropyGen1, plain)) {
		out.resize((int)plain.size());
		memcpy(out.ptrw(), plain.ptr(), (size_t)plain.size());
		return out;
	}
	// 兼容读取：历史自编译版曾用 kEntropyGen2 封装 0.bin 与 profile.cfg 的 wrapped_key。
	// 官方版从不使用这把熵做 v1 段，但为了不丢用户既有的本地数据，读路径保留一次兜底。
	if (dpapi_unprotect_with_entropy(cipher, kEntropyGen2, plain)) {
		out.resize((int)plain.size());
		memcpy(out.ptrw(), plain.ptr(), (size_t)plain.size());
	}
	// 早期“裸异或 keystream1”格式不再兜底：那种解出来的东西必然不是官方可读格式，
	// 继续尝试只会让上层把坏数据当成好数据（上一版 T4_MARKS_BROKEN 的连带原因）。
#else
	out = in;
#endif
	return out;
}

// [修正 2026-11-18 二次] 官方 0x340DCB0 只有一次调用：
//   CryptProtectData(pDataIn = 输入, szDataDescr = L"ombrel",
//       pOptionalEntropy = machine_secret32()（32 B）, NULL, NULL,
//       dwFlags = 5 = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE)
// 不产任何自造头。上一版的 "[1][16B 标签]" 前缀属臆造：官方 device_unwrap_m
// （0x340DED0）把整块交给 CryptUnprotectData，多 17 字节头会直接 DataInvalid。
//
// machine_secret32 官方由 0x340F6E0 派生（CryptAcquireContextW + CryptGetProvParam
// 枚举本机 CSP 名 → 拼 "xiewa-machine2" + provider 名 → KDF 出 32 B），依赖运行时
// CSP 列表，离线无法复刻；这里改用 0.bin 里的 32 B 设备种子（同为“本机 DPAPI 绑定的
// 材料”），保住“本机可写可读、异机不可解”的语义，且不再破坏官方容器布局。
PackedByteArray XiewaGuard::device_wrap_m(const PackedByteArray &in) {
	PackedByteArray out;
#ifdef WINDOWS_ENABLED
	uint8_t seed[32];
	if (!device_seed32(seed)) {
		return out;
	}
	Vector<uint8_t> plain;
	plain.resize(in.size());
	if (in.size() > 0) {
		memcpy(plain.ptrw(), in.ptr(), (size_t)in.size());
	}
	Vector<uint8_t> cipher;
	if (!dpapi_protect_machine(plain, seed, cipher)) {
		return out;
	}
	out.resize((int)cipher.size());
	memcpy(out.ptrw(), cipher.ptr(), (size_t)cipher.size());
#else
	out = in;
#endif
	return out;
}

// 官方 0x340DED0：一次 CryptUnprotectData(entropy = machine_secret32(), flags = 5)，
// 解不开返回空（与 v1 user 段失败即空的行为一致，没有容器剥壳、没有 keystream 反异或）。
PackedByteArray XiewaGuard::device_unwrap_m(const PackedByteArray &in) {
	PackedByteArray out;
#ifdef WINDOWS_ENABLED
	if (in.size() == 0) {
		return out;
	}
	uint8_t seed[32];
	if (!device_seed32(seed)) {
		return out;
	}
	Vector<uint8_t> cipher;
	cipher.resize(in.size());
	memcpy(cipher.ptrw(), in.ptr(), (size_t)in.size());
	Vector<uint8_t> plain;
	if (!dpapi_unprotect_machine(cipher, seed, plain)) {
		return out;
	}
	out.resize((int)plain.size());
	memcpy(out.ptrw(), plain.ptr(), (size_t)plain.size());
#else
	(void)in;
#endif
	return out;
}

// =============================================================================
//  设备标签 / pepper（0x340E0F0 1938 B / 0x340E890 461 B）
//  实测两者长度差 4 倍，不是同一个函数
// =============================================================================
String XiewaGuard::device_tag(const String &seed) {
#ifdef WINDOWS_ENABLED
	// [修正 2026-11-18 二次] 官方 0x340E0F0 逐指令实证，device_tag(path) 不是“拼系统信息再哈希”：
	//   1) FileAccess 打开 path 读全部字节；
	//   2) call device_unwrap（0x340DA40 = CryptUnprotectData + entropy kEntropyGen1）；
	//   3) 解出长度必须 == 0x20，否则判失败；
	//   4) 把该 32 B 填进 {buf[64]; len=32@64; pad; h[8]=SHA256 IV@72/88; tail@104} 结构，
	//      调 0x2BFE6F0 / 0x2BFF3D0，输出 16 B；
	//   5) 用 "0123456789abcdef" 把 16 B 转 32 个 hex 字符返回。
	// 第 4 步是“SHA-256 上下文但只吐 16 B”，实测不等于 sha256/md5/sha1 的任意前缀
	// （目标 b64dda373fad133 至今未被任何候选命中），说明它截断位置不标准。
	// 该值只作 machine 段头与日志里的“设备代号”，官方解我方数据时不校验它
	// （device_unwrap_m2 只跳过 17 字节头），因此这里用标准 SHA-256 取前 32 个 hex 字符：
	// 长度、字符集、同机稳定性与官方一致。
	String path = seed;
	if (path.is_empty()) {
		String base = OS::get_singleton()->get_environment("LOCALAPPDATA");
		if (!base.is_empty()) {
			path = base.replace("\\", "/") + "/" + vendor() + "/" + cache_dir() + "/0.bin";
		}
	}
	PackedByteArray blob;
	if (!path.is_empty()) {
		Ref<FileAccess> f = FileAccess::open(path, FileAccess::READ);
		if (!f.is_null()) {
			blob = f->get_buffer((int)f->get_length());
			f.unref();
		}
	}
	uint8_t d[32];
	bool have_seed = false;
	if (blob.size() > 0) {
		Vector<uint8_t> plain;
		if (dpapi_unprotect_with_entropy(blob, kEntropyGen1, plain) && plain.size() == 32) {
			memcpy(d, plain.ptr(), 32);
			have_seed = true;
		}
	}
	if (!have_seed) {
		// 与官方一致：种子缺失时现生成 32 B，用 device_wrap 封好写回该 path，
		// 保证同一台机器后续每次得到同一个 tag。
		for (int i = 0; i < 32; i++) {
			d[i] = (uint8_t)(uint32_t)Math::rand();
		}
		if (!path.is_empty()) {
			PackedByteArray raw;
			raw.resize(32);
			memcpy(raw.ptrw(), d, 32);
			PackedByteArray wrapped = device_wrap(raw);
			if (wrapped.size() > 0) {
				Ref<FileAccess> f = FileAccess::open(path, FileAccess::WRITE);
				if (!f.is_null()) {
					f->store_buffer(wrapped);
					f.unref();
				}
			}
		}
	}
	uint8_t h[32];
	util::sha256(d, 32, h);
	return util::to_hex32(h).substr(0, 32);
#else
	(void)seed;
	return String("unavailable");
#endif
}

// [修正 2026-11-17] pepper 是**与机器无关的静态生成器**，不是设备指纹派生量。
//   反汇编 0x14340E890（461 B）：两张 .rdata 表 + 逐两字节摊平
//     A @ 0x1450A3100 = 8becc2e515384b8d75b902a9da95114d69bb47ceb7d67d4f3f2c5be5eab42b5c
//     B @ 0x1450A3120 = f6231ea02c9f3a864624d77dfda4b133d330058d8b5decfc2e239ca6058fa7bd
//     k = 0..15
//     rax = 1 + 2k ; ecx = 0x12 + 0x1A*k ; dl = 0x3B + 0x76*k
//     out[rax-1] = (B[((ecx - 0x0D) & 0x1F)] + dl + 0xC5) ^ A[rax-1]
//     out[rax]   = (B[(ecx & 0x1E)]         + dl)        ^ A[rax]
//   整体复算 = 14acf14b1a59a41e0916d6bd3d25f1f664b21ea87715cf6f28b6a1804ee24c0f
//   （与 kEntropyGen1 同值：v1 的 DPAPI 熵正是拿 pepper 当熵）
//   pepper 是「迁移文件 mac（_kt → hkdf_expand(pepper, …)）」「日志行 mac」的密钥根，
//   一旦猜错会让所有 HMAC 对不上 —— 迁移导入报「迁移文件校验失败」即由此而来。
static const uint8_t kPepperBytes[32] = {
	0x14, 0xAC, 0xF1, 0x4B, 0x1A, 0x59, 0xA4, 0x1E,
	0x09, 0x16, 0xD6, 0xBD, 0x3D, 0x25, 0xF1, 0xF6,
	0x64, 0xB2, 0x1E, 0xA8, 0x77, 0x15, 0xCF, 0x6F,
	0x28, 0xB6, 0xA1, 0x80, 0x4E, 0xE2, 0x4C, 0x0F,
};

PackedByteArray XiewaGuard::pepper() {
	PackedByteArray out;
	out.resize(32);
	uint8_t *w = out.ptrw();
	memcpy(w, kPepperBytes, 32);
	return out;
}

// =============================================================================
//  注册表三件（0x340EA60 / 0x340ECE0 / 0x340F0F0）
// =============================================================================
// 0x340EA60：脚本契约是 reg_write(vendor, subkey, name, data)
//   路径 = "Software\" + vendor + "\" + subkey；值名 = name；值 = data（REG_BINARY）
bool XiewaGuard::reg_write(const String &vendor_name, const String &subkey, const String &name,
		const PackedByteArray &data) {
#ifdef WINDOWS_ENABLED
	String path = String("Software\\") + (vendor_name.is_empty() ? vendor() : vendor_name) +
			"\\" + (subkey.is_empty() ? reg_subkey() : subkey);
	if (name.is_empty()) {
		return false;
	}
	Vector<uint8_t> raw;
	raw.resize(data.size());
	if (data.size() > 0) {
		memcpy(raw.ptrw(), data.ptr(), (size_t)data.size());
	}
	return util::reg_write_binary(HKEY_CURRENT_USER, path, name, raw);
#else
	(void)vendor_name;
	(void)subkey;
	(void)name;
	(void)data;
	return false;
#endif
}

// 0x340ECE0：脚本契约是 reg_read(vendor, subkey, name) → PackedByteArray
//   路径 = "Software\" + vendor + "\" + subkey；值名 = name；未命中返回空字节
PackedByteArray XiewaGuard::reg_read(const String &vendor_name, const String &subkey, const String &name) {
	PackedByteArray out;
#ifdef WINDOWS_ENABLED
	String path = String("Software\\") + (vendor_name.is_empty() ? vendor() : vendor_name) +
			"\\" + (subkey.is_empty() ? reg_subkey() : subkey);
	if (name.is_empty()) {
		return out;
	}
	Vector<uint8_t> raw;
	if (util::reg_read_binary(HKEY_CURRENT_USER, path, name, raw) && raw.size() > 0) {
		out.resize((int)raw.size());
		memcpy(out.ptrw(), raw.ptr(), (size_t)raw.size());
	}
#else
	(void)vendor_name;
	(void)subkey;
	(void)name;
#endif
	return out;
}

// 0x340F0F0（559 B）：HKCU + KEY_SET_VALUE(2) + RegDeleteValueW；
// "Software\" + subkey 为路径，value 为值名，两步都成功才 true
// 0x340F0F0（559 B）：HKCU + KEY_SET_VALUE(2) + RegDeleteValueW
//   脚本契约是 reg_erase(vendor, subkey, name)：路径 "Software\vendor\subkey"，删值 name
bool XiewaGuard::reg_erase(const String &vendor_name, const String &subkey, const String &name) {
#ifdef WINDOWS_ENABLED
	String path = String("Software\\") + (vendor_name.is_empty() ? vendor() : vendor_name) +
			"\\" + (subkey.is_empty() ? reg_subkey() : subkey);
	if (name.is_empty()) {
		return false;
	}
	return util::reg_delete_value(HKEY_CURRENT_USER, path, name);
#else
	(void)vendor_name;
	(void)subkey;
	(void)name;
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
bool XiewaGuard::single_instance_acquire(const String &name) {
#ifdef WINDOWS_ENABLED
	if (g_instance_mutex != nullptr) {
		return true;
	}
	// 原程序 argc=1：互斥体名由脚本给；空串时退回 mutex_name() 的固定 GUID
	String mtx = name.is_empty() ? mutex_name() : name;
	std::wstring wname = util::wide(mtx);
	HANDLE h = CreateMutexW(nullptr, TRUE, wname.c_str());
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
	(void)name;
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
