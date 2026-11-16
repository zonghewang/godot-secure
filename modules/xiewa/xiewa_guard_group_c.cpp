// =============================================================================
//  XiewaGuard_组C.cpp —— 桥接 / 授权 / 清单 21 条的真实实现
//  绑定批 0x3910350；绑定点 0x3910471 … 0x39111B8；16 个唯一实现体（5 组同体）
//
//  共享件回落：0x39054B0(全局取用) / 0x38F7B60(副本扫描) / 0x38FD050(状态对象)
//              0x390C520(摘要内核) / 0x390B240(清单校验) / 0x390EA40(unseal 通道)
//              0x39194E0(SHA-256) / 0x391BD00(HMAC-SHA-256)
//  清单文件：<exe目录>\resources\安全\xiewa_list.txt（XWL1 + base64 JSON + 签名）
// =============================================================================

#include "xiewa_guard.h"
#include "xiewa_guard2d.h"
#include "xiewa_util.h"

#include "core/io/dir_access.h"
#include "core/io/file_access.h"
#include "core/os/os.h"
#include "core/variant/array.h"
#include "core/variant/dictionary.h"

#if __has_include("core/variant/json.h")
#include "core/variant/json.h"
#else
#include "core/io/json.h"
#endif

#ifdef WINDOWS_ENABLED
#include <windows.h>
#endif

namespace xiewa {

namespace {

Dictionary g_list_state;      // list_apply / list_state 共用的状态
Dictionary g_defer_state;     // defer_note / defer_boot / defer_state
bool g_defer_inited = false;
bool g_list_ready = false;
String g_list_raw;

String list_path() {
	return OS::get_singleton()->get_executable_path().get_base_dir() + "/resources/安全/xiewa_list.txt";
}

String cache_root() {
#ifdef WINDOWS_ENABLED
	String base = OS::get_singleton()->get_user_data_dir();
	return base + "/ombrel_cache";
#else
	return String("user://ombrel_cache");
#endif
}

String machine_fp_impl() {
#ifdef WINDOWS_ENABLED
	String acc;
	// ① 系统盘卷序列号
	wchar_t root[4] = { L'C', L':', L'\\', 0 };
	String sysdir = util::system_dir();
	if (sysdir.length() >= 2) {
		root[0] = (wchar_t)sysdir[0];
	}
	DWORD serial = 0;
	wchar_t label[256], fs[256];
	if (GetVolumeInformationW(root, label, 256, &serial, nullptr, nullptr, fs, 256)) {
		acc += String::num_uint64(serial) + "|";
	}
	// ② MachineGuid
	String guid;
	if (util::reg_read_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", guid)) {
		acc += guid + "|";
	}
	// ③ SMBIOS type1 UUID
	DWORD size = GetSystemFirmwareTable(0x5253424Du, 0u, nullptr, 0);
	if (size >= 16) {
		Vector<uint8_t> buf;
		buf.resize((int)size);
		if (GetSystemFirmwareTable(0x5253424Du, 0u, buf.ptrw(), size) == size) {
			const uint8_t *p = buf.ptr();
			uint32_t pos = 8;
			while (pos + 4 <= size) {
				uint8_t type = p[pos];
				uint8_t len = p[pos + 1];
				if (len < 4) {
					break;
				}
				if (type == 1 && len >= 0x19) {
					acc += util::to_hex(p + pos + 8, 16) + "|";
					break;
				}
				pos += len;
				while (pos + 1 < size && !(p[pos] == 0 && p[pos + 1] == 0)) {
					pos++;
				}
				pos += 2;
			}
		}
	}
	// ④ Windows 目录 + 处理器数
	acc += util::system_dir() + "|";
	acc += String::num_int64(OS::get_singleton()->get_processor_count());

	uint8_t d[32];
	CharString u8 = acc.utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), d);
	return util::to_hex32(d);
#else
	return String("unavailable");
#endif
}

// 清单 JSON 解析（XWL1 头 + base64 载荷）
Dictionary parse_list(const String &p_text, bool *r_xwl1) {
	Dictionary out;
	if (r_xwl1) {
		*r_xwl1 = p_text.begins_with("XWL1");
	}
	Variant parsed = JSON::parse_string(p_text);
	if (parsed.get_type() == Variant::DICTIONARY) {
		return parsed;
	}
	// 退一步：整体可能是 base64
	Vector<uint8_t> raw = util::b64_decode(p_text);
	if (raw.size() > 0) {
		Variant again = JSON::parse_string(String::utf8((const char *)raw.ptr(), raw.size()));
		if (again.get_type() == Variant::DICTIONARY) {
			return again;
		}
	}
	return out;
}

bool load_list() {
	String path = list_path();
	Ref<FileAccess> fa = FileAccess::open(path, FileAccess::READ);
	if (fa.is_null()) {
		return false;
	}
	g_list_raw = fa->get_as_text();
	g_list_state = parse_list(g_list_raw, nullptr);
	g_list_ready = !g_list_state.is_empty();
	return g_list_ready;
}

// 清单里的 bans 数组：{h, s, k, n}
Array list_bans() {
	Array bans;
	if (g_list_state.has("bans")) {
		Variant v = g_list_state["bans"];
		if (v.get_type() == Variant::ARRAY) {
			bans = v;
		}
	}
	return bans;
}

} // namespace

// =============================================================================
//  bridge_check（0x38F7AD0，26 条指令）
//  CS 包裹 → 0x39054B0 取全局 → 副本扫描 → if (flags & 2) 把返回值收敛到 0x63
// =============================================================================
int XiewaGuard::bridge_check(int flags) {
	int ret = flags;
	if ((flags & 2) != 0) {
		ret &= 0x63;
	}
#ifdef WINDOWS_ENABLED
	// 副本扫描（0x38F7B60）：可执行文件不在自身目录时，收敛掩码
	String self = OS::get_singleton()->get_executable_path();
	if (self.find("\\Temp\\") >= 0) {
		ret &= 0x63;
	}
#endif
	return ret;
}

// =============================================================================
//  script_integrity（0x3E13260）
//  真身就是 xiewa_guard2d 那套自校验，返回 "bits"/"high"/"container"
//  这里按观测到的三值语义折算成字符串
// =============================================================================
String XiewaGuard::script_integrity(const Variant &opts) {
	Dictionary cfg;
	if (opts.get_type() == Variant::DICTIONARY) {
		cfg = opts;
	}
	Dictionary r = xiewa_guard2d::impl::script_integrity_impl(cfg);
	int bits = r.has("bits") ? (int)(int64_t)r["bits"] : 0;
	int high = r.has("high") ? (int)(int64_t)r["high"] : (bits & 0x7F);

	if ((bits & 0x7F) == 0 && high == 0) {
		return String("bad");
	}
	if (high != 0) {
		return String("high");
	}
	return String("none");
}

// =============================================================================
//  engine_flags（0x38F8820）
//  "Ombrel"/"Cache" → reg_read → JSON 读 LOCALAPPDATA / PROGRAMDATA → 标记集合
// =============================================================================
Variant XiewaGuard::engine_flags() {
	Dictionary out;
	out["container"] = Array();
	out["reg"] = reg_read("engine_flags");

	Array dirs;
	dirs.push_back(OS::get_singleton()->get_data_path());
#ifdef WINDOWS_ENABLED
	{
		wchar_t prog[512];
		DWORD n = GetEnvironmentVariableW(L"ProgramData", prog, 512);
		if (n > 0) {
			out["program_data"] = util::narrow(prog, (int)n);
		}
	}
#endif
	out["dirs"] = dirs;
	out["ver"] = 7;
	return out;
}

// =============================================================================
//  machine_fp / devlimit_state（0x38F7230，两方法同体）
// =============================================================================
String XiewaGuard::machine_fp() {
	return machine_fp_impl();
}

String XiewaGuard::devlimit_state() {
	return machine_fp_impl();
}

// =============================================================================
//  devlimit_mark（0x38FBE00）：写 ev / at / fp 三个字段
// =============================================================================
Variant XiewaGuard::devlimit_mark(const Variant &v) {
	Dictionary out;
	out["ok"] = false;

	Dictionary rec;
	String ev;
	if (v.get_type() == Variant::DICTIONARY) {
		Dictionary d = v;
		if (d.has("ev")) {
			ev = (String)d["ev"];
		}
		rec = d;
	} else if (v.get_type() == Variant::STRING) {
		ev = v;
	}
	if (ev.is_empty()) {
		out["err"] = String("event");
		return out;
	}

	OS::DateTime now = OS::get_singleton()->get_datetime();
	auto pad2 = [](int p_v) -> String {
		return p_v < 10 ? String("0") + String::num_int64(p_v) : String::num_int64(p_v);
	};
	String at = String::num_int64(now.year) + "-" + pad2(now.month) + "-" + pad2(now.day) + "T" +
			pad2(now.hour) + ":" + pad2(now.minute) + ":" + pad2(now.second);
	rec["ev"] = ev;
	rec["at"] = at;
	rec["fp"] = machine_fp_impl();

	String dir = cache_root();
	DirAccess::make_dir_recursive_absolute(dir);
	String path = dir + "/devlimit.txt";
	Ref<FileAccess> fa = FileAccess::open(path, FileAccess::WRITE);
	if (fa.is_null()) {
		out["err"] = String("container");
		return out;
	}
	fa->store_string(JSON::stringify(rec));
	fa->flush();

	out["ok"] = true;
	out["at"] = rec["at"];
	return out;
}

// =============================================================================
//  devlimit_clear（0x390E670）："XIEWA-UNSEAL|" + … + "|M" → 清理 Cache 下记录
// =============================================================================
Variant XiewaGuard::devlimit_clear(const Variant &v) {
	Dictionary out;
	out["ok"] = false;
	out["cleared"] = 0;

	String token = "XIEWA-UNSEAL|";
	if (v.get_type() == Variant::STRING) {
		token = (String)v;
	}
	if (!token.begins_with("XIEWA-UNSEAL|")) {
		out["err"] = String("format");
		return out;
	}

	String dir = cache_root();
	Ref<DirAccess> da = DirAccess::open(dir);
	if (da.is_valid()) {
		da->list_dir_begin();
		String f = da->get_next();
		int n = 0;
		while (!f.is_empty()) {
			if (!da->current_is_dir()) {
				if (DirAccess::remove_absolute(dir.path_join(f)) == OK) {
					n++;
				}
			}
			f = da->get_next();
		}
		da->list_dir_end();
		out["cleared"] = n;
	}
	out["ok"] = true;
	return out;
}

// =============================================================================
//  defer_note / defer_boot / defer_state（0x38FC640 / 0x38FF4C0）
//  键：all / ev / first / need_d / need_n；defer_boot 与 defer_state 同体
// =============================================================================
Variant XiewaGuard::defer_note(const Variant &v) {
	Dictionary out;
	if (!g_defer_inited) {
		g_defer_state = Dictionary();
		g_defer_inited = true;
	}
	if (v.get_type() != Variant::DICTIONARY) {
		return g_defer_state;
	}
	Dictionary d = v;
	for (const char *k : { "all", "ev", "first", "need_d", "need_n" }) {
		if (d.has(k)) {
			g_defer_state[k] = d[k];
		}
	}
	// all 置位时把其余键一起抄进来（对应 0x38FC640 的展开分支）
	if (d.has("all") && (bool)d["all"]) {
		for (int i = 0; i < d.size(); i++) {
			Variant key = d.get_key_at_index(i);
			g_defer_state[key] = d.get_value_at_index(i);
		}
	}
	out = g_defer_state;
	out["ok"] = true;
	return out;
}

Variant XiewaGuard::defer_boot(const Variant &v) {
	// 0x38FF4C0：全局 0x548B148 首次标志 + Variant 类型 switch（cmp ecx,3 / ja / jmp 跳表）
	if (!g_defer_inited) {
		g_defer_state = Dictionary();
		g_defer_inited = true;
	}
	if (v.get_type() == Variant::DICTIONARY) {
		Dictionary d = v;
		for (const char *k : { "first", "need_n", "need_d" }) {
			if (d.has(k)) {
				g_defer_state[k] = d[k];
			}
		}
	} else if (v.get_type() == Variant::INT) {
		g_defer_state["need_n"] = v;
	} else if (v.get_type() == Variant::STRING) {
		g_defer_state["ev"] = v;
	}

	Dictionary out = g_defer_state;
	int need_n = out.has("need_n") ? (int)(int64_t)out["need_n"] : 0;
	int need_d = out.has("need_d") ? (int)(int64_t)out["need_d"] : 0;
	bool first = out.has("first") ? (bool)out["first"] : true;

	// 延期判定：首次运行或期限已到都放行
	bool expired = false;
	if (need_d > 0 && out.has("ev")) {
		expired = true;
	}
	out["defer"] = !(first || need_n == 0 || expired);
	out["ok"] = true;
	return out;
}

Variant XiewaGuard::defer_state() {
	return defer_boot(Variant());
}

// =============================================================================
//  list_apply / list_state（0x3906250，同体）
//  字段：container / ok / changed / err / ver / sig / old / format
// =============================================================================
Variant XiewaGuard::list_apply(const Variant &v) {
	Dictionary out = g_list_state;
	out["ok"] = false;

	if (v.get_type() != Variant::DICTIONARY) {
		out["err"] = String("format");
		return out;
	}
	Dictionary d = v;
	if (!d.has("container")) {
		out["err"] = String("container");
		return out;
	}

	Dictionary prev = g_list_state;
	g_list_state = d;
	g_list_state["ok"] = true;
	g_list_state["changed"] = !prev.is_empty() && (String)prev.get("sig", "") != (String)d.get("sig", "");
	g_list_state["ver"] = d.has("ver") ? d["ver"] : Variant(0);
	g_list_state["format"] = d.has("format") ? d["format"] : Variant(String("XWL1"));
	if (d.has("sig")) {
		g_list_state["sig"] = d["sig"];
	}

	out = g_list_state;
	out["old"] = prev;
	g_list_ready = true;
	return out;
}

Variant XiewaGuard::list_state() {
	Dictionary out = g_list_state;
	if (out.is_empty()) {
		load_list();
		out = g_list_state;
	}
	out["ready"] = g_list_ready;
	return out;
}

// =============================================================================
//  list_raw（0x390C7E0，135 B）：CS 包裹，返回原始清单串
// =============================================================================
String XiewaGuard::list_raw() {
	if (g_list_raw.is_empty()) {
		load_list();
	}
	return g_list_raw;
}

// =============================================================================
//  list_check_profile（0x390C860）：按 profile 匹配 bans 里的 k 字段
// =============================================================================
Variant XiewaGuard::list_check_profile(const String &profile) {
	Dictionary out;
	out["ok"] = true;
	out["match"] = false;
	out["profile"] = profile;

	if (g_list_state.is_empty() && !load_list()) {
		out["ok"] = false;
		out["err"] = String("unavailable");
		return out;
	}
	Array bans = list_bans();
	for (int i = 0; i < bans.size(); i++) {
		Variant e = bans[i];
		if (e.get_type() != Variant::DICTIONARY) {
			continue;
		}
		Dictionary b = e;
		String k = b.has("k") ? (String)b["k"] : String();
		if (k == profile) {
			out["match"] = true;
			out["entry"] = b;
			break;
		}
	}
	return out;
}

// =============================================================================
//  id_hash（0x390CB50，49 B）：String 有效性判定 → 摘要内核
// =============================================================================
String XiewaGuard::id_hash(const String &id) {
	if (id.is_empty()) {
		return String();
	}
	uint8_t d[32];
	CharString u8 = id.utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), d);
	return util::to_hex32(d);
}

// =============================================================================
//  list_check_hash（0x390CA20，79 B）：要求 17 字符（cmp dword[arg-0x10],0x11）
//  同体：svc_verify / ck_state
// =============================================================================
Variant XiewaGuard::list_check_hash(const String &hash) {
	Dictionary out;
	out["ok"] = false;
	out["match"] = false;

	// 基线 h 字段是 16 字符 + 结尾，故要求 17（含长度校验的历史行为）
	if (hash.length() != 16 && hash.length() != 17) {
		out["err"] = String("format");
		return out;
	}
	if (g_list_state.is_empty() && !load_list()) {
		out["err"] = String("unavailable");
		return out;
	}
	Array bans = list_bans();
	for (int i = 0; i < bans.size(); i++) {
		Variant e = bans[i];
		if (e.get_type() != Variant::DICTIONARY) {
			continue;
		}
		Dictionary b = e;
		if (!b.has("h")) {
			continue;
		}
		if (util::ct_equal((String)b["h"], hash.substr(0, 16))) {
			out["match"] = true;
			out["ok"] = true;
			out["entry"] = b;
			return out;
		}
	}
	out["ok"] = true;
	return out;
}

Variant XiewaGuard::svc_verify(const String &sig) {
	return list_check_hash(sig);
}

Variant XiewaGuard::ck_state() {
	Dictionary out;
	if (g_list_state.is_empty()) {
		load_list();
	}
	out["ready"] = g_list_ready;
	out["mode"] = g_list_state.has("mode") ? g_list_state["mode"] : Variant(String("off"));
	out["ver"] = g_list_state.has("ver") ? g_list_state["ver"] : Variant(0);
	out["bans"] = list_bans().size();
	return out;
}

// =============================================================================
//  unseal_receipt（0x390F1A0，331 B）
//  "XIEWA-UNSEAL|" + key + "|M" → 0x390EA40 解析 → machine / receipt / ok
// =============================================================================
String XiewaGuard::unseal_receipt(const String &key) {
	if (key.is_empty()) {
		return String();
	}
	String token = "XIEWA-UNSEAL|" + key + "|M";
	uint8_t mac[32];
	util::hmac_sha256(pepper(), token, mac);
	String receipt = util::to_hex32(mac);
	return String("machine=") + machine_fp_impl().substr(0, 16) +
			";receipt=" + receipt + ";ok=1";
}

// =============================================================================
//  receipt_ok（0x390FFA0，68 B）：0x390F8A0 拆分后分段比较
// =============================================================================
bool XiewaGuard::receipt_ok(const String &receipt, const String &expect) {
	if (receipt.is_empty() || expect.is_empty()) {
		return false;
	}
	// 按 ';' 拆段，逐段比对（cmp r8d,eax / shl r8,2 的形态是逐段长度比较）
	Vector<String> segs_a = receipt.split(";");
	Vector<String> segs_b = expect.split(";");
	if (segs_a.size() != segs_b.size()) {
		return false;
	}
	for (int i = 0; i < segs_a.size(); i++) {
		if (!util::ct_equal(segs_a[i], segs_b[i])) {
			return false;
		}
	}
	return true;
}

// =============================================================================
//  unseal_legacy_ok（0x3910070，184 B）：0x8A2660 + 16 字符切片比较
// =============================================================================
bool XiewaGuard::unseal_legacy_ok(const String &receipt) {
	if (receipt.length() < 16) {
		return false;
	}
	String fp = machine_fp_impl().substr(0, 16);
	if (fp.length() < 16) {
		return false;
	}
	return util::ct_equal(receipt.substr(0, 16), fp);
}

} // namespace xiewa
