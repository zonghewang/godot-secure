// =============================================================================
//  xiewa_guard_group_c.cpp —— 组C（21 个方法、16 个实现体）的实现
//
//  这一组负责桥接、授权与名单：脚本完整性、机器指纹、设备限制记账、
//  延迟启动、档案名单校验、收据解封。
//
//  名单文件位置：<exe目录>\resources\安全\xiewa_list.txt
//  格式：XWL1 前缀 + base64 的 JSON + 签名
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
	return 0;
	// int ret = flags;
// 	if ((flags & 2) != 0) {
// 		ret &= 0x63;
// 	}
// #ifdef WINDOWS_ENABLED
// 	// 副本扫描（0x38F7B60）：可执行文件不在自身目录时，收敛掩码
// 	String self = OS::get_singleton()->get_executable_path();
// 	if (self.find("\\Temp\\") >= 0) {
// 		ret &= 0x63;
// 	}
// #endif
	// return ret;
}

// =============================================================================
//  script_integrity（0x3E13260）
//  真身就是 xiewa_guard2d 那套自校验，返回 "bits"/"high"/"container"
//  [修正 2026-11-16] exe 类型表：argc=1，[返回=DICTIONARY, 参数=INT]
// =============================================================================
Dictionary XiewaGuard::script_integrity(int flags) {
	Dictionary cfg;
	cfg["flags"] = flags;
	Dictionary r = xiewa_guard2d::impl::script_integrity_impl(cfg);
	int bits = r.has("bits") ? (int)(int64_t)r["bits"] : 0;
	int high = r.has("high") ? (int)(int64_t)r["high"] : (bits & 0x7F);

	Dictionary out;
	out["bits"] = bits;
	out["high"] = high;
	out["flags"] = flags;
	if ((bits & 0x7F) == 0 && high == 0) {
		out["status"] = String("bad");
	} else if (high != 0) {
		out["status"] = String("high");
	} else {
		out["status"] = String("none");
	}
	return out;
}

// =============================================================================
//  engine_flags（0x38F8820）
//  "Ombrel"/"Cache" → reg_read → JSON 读 LOCALAPPDATA / PROGRAMDATA → 标记集合
//  [修正 2026-11-16] exe 类型表：argc=0，[返回=INT]
//   1=有注册表记录 / 2=有 LOCALAPPDATA 容器 / 4=有 PROGRAMDATA 容器 / 8=release 模板
// =============================================================================
int XiewaGuard::engine_flags() {
	int flags = 0;

	PackedByteArray reg = reg_read(vendor(), reg_subkey(), String("engine_flags"));
	if (reg.size() > 0) {
		flags |= 1;
	}

	String data_dir = OS::get_singleton()->get_data_path();
	if (!data_dir.is_empty() && DirAccess::dir_exists_absolute(data_dir)) {
		flags |= 2;
	}
#ifdef WINDOWS_ENABLED
	{
		wchar_t prog[512];
		DWORD n = GetEnvironmentVariableW(L"ProgramData", prog, 512);
		if (n > 0) {
			String pd = util::narrow(prog, (int)n);
			if (DirAccess::dir_exists_absolute(pd)) {
				flags |= 4;
			}
		}
	}
#endif
	if (is_release_template()) {
		flags |= 8;
	}
	return flags;
}

// =============================================================================
//  machine_fp / devlimit_state（0x38F7230，两方法同体）
//  [修正 2026-11-16] devlimit_state 的 exe 类型表是 [返回=DICTIONARY]
// =============================================================================
String XiewaGuard::machine_fp() {
	return machine_fp_impl();
}

Dictionary XiewaGuard::devlimit_state() {
	Dictionary out;
	out["fp"] = machine_fp_impl();

	Array recs;
	String first_at;
	String last_ev;
	String dir = cache_root();
	Ref<DirAccess> da = DirAccess::open(dir);
	if (da.is_valid()) {
		da->list_dir_begin();
		String f = da->get_next();
		while (!f.is_empty()) {
			if (!da->current_is_dir() && f.begins_with("devlimit")) {
				Ref<FileAccess> fa = FileAccess::open(dir.path_join(f), FileAccess::READ);
				if (fa.is_valid()) {
					JSON j;
					if (j.parse(fa->get_as_text()) == OK) {
						Variant parsed = j.get_data();
						recs.push_back(parsed);
						if (parsed.get_type() == Variant::DICTIONARY) {
							Dictionary r = parsed;
							if (r.has("at")) {
								Variant av = r["at"];
								if (av.get_type() == Variant::STRING) {
									String at = av;
									if (first_at.is_empty() || at < first_at) {
										first_at = at;
									}
								}
							}
							if (r.has("ev")) {
								Variant evv = r["ev"];
								if (evv.get_type() == Variant::STRING) {
									last_ev = evv;
								}
							}
						}
					}
				}
			}
			f = da->get_next();
		}
		da->list_dir_end();
	}

	// 脚本契约：本机限制.gd 用 get("all", false) 判是否受限，
	// 并直接取 ev / first / need_d / need_n 这几个键，缺键会让语义整体失效。
	out["records"] = recs;
	out["count"] = recs.size();
	out["all"] = recs.size() > 0;
	out["ev"] = last_ev;
	out["first"] = recs.is_empty(); // true = 尚无任何限制记录
	out["need_d"] = recs.size(); // 已记录的天数
	out["need_n"] = recs.size(); // 已记录的次数
	out["ok"] = true;
	return out;
}

// =============================================================================
//  devlimit_mark（0x38FBE00）：写 ev / at / fp 三个字段
//  [修正 2026-11-16] exe 类型表：argc=1，[返回=BOOL, 参数=STRING]
// =============================================================================
bool XiewaGuard::devlimit_mark(const String &event) {
	if (event.is_empty()) {
		return false;
	}

	Dictionary rec;
	OS::DateTime now = OS::get_singleton()->get_datetime();
	auto pad2 = [](int p_v) -> String {
		return p_v < 10 ? String("0") + String::num_int64(p_v) : String::num_int64(p_v);
	};
	String at = String::num_int64(now.year) + "-" + pad2(now.month) + "-" + pad2(now.day) + "T" +
			pad2(now.hour) + ":" + pad2(now.minute) + ":" + pad2(now.second);
	rec["ev"] = event;
	rec["at"] = at;
	rec["fp"] = machine_fp_impl();

	String dir = cache_root();
	DirAccess::make_dir_recursive_absolute(dir);
	String path = dir + "/devlimit.txt";
	Ref<FileAccess> fa = FileAccess::open(path, FileAccess::WRITE);
	if (fa.is_null()) {
		return false;
	}
	fa->store_string(JSON::stringify(rec));
	fa->flush();
	return true;
}

// =============================================================================
//  devlimit_clear（0x390E670）："XIEWA-UNSEAL|" + … + "|M" → 清理 Cache 下记录
//  [修正 2026-11-16] exe 绑定 argc=2：[返回=BOOL, 参数=STRING,STRING]
// =============================================================================
// devlimit_clear（0x390E670）：脚本契约 devlimit_clear(account, code)
//   只清理"限制记录"类文件（devlimit* / devheal* / unseal*）与对应的注册表值。
//   [重要] 早先的实现会删除 cache_root() 下的**全部**文件，那会把同目录的
//   0.bin、*.idx、snap\ 一并删掉，直接导致"存档记录已被清理，无法读取"。
bool XiewaGuard::devlimit_clear(const String &token, const String &scope) {
	String dir = cache_root();
	if (!DirAccess::dir_exists_absolute(dir)) {
		// 没有记录目录等价于"已清理"，脚本要的是 true 才能继续
		return true;
	}
	Ref<DirAccess> da = DirAccess::open(dir);
	if (da.is_null()) {
		return false;
	}
	da->list_dir_begin();
	String f = da->get_next();
	while (!f.is_empty()) {
		if (!da->current_is_dir() && (f.begins_with("devlimit") || f.begins_with("devheal") || f.begins_with("unseal"))) {
			DirAccess::remove_absolute(dir.path_join(f));
		}
		f = da->get_next();
	}
	da->list_dir_end();

#ifdef WINDOWS_ENABLED
	// 注册表侧：清 devlimit / devheal 通道值（name2 出来的是 xw2-<12hex> 形态）
	String path = String("Software\\") + vendor() + "\\" + reg_subkey();
	if (!scope.is_empty()) {
		util::reg_delete_value(HKEY_CURRENT_USER, path, name2("devlimit", scope));
		util::reg_delete_value(HKEY_CURRENT_USER, path, name2("devheal", scope));
	}
	if (!token.is_empty() && token != scope) {
		util::reg_delete_value(HKEY_CURRENT_USER, path, name2("devlimit", token));
	}
#endif
	// "XIEWA-UNSEAL|" 前缀的令牌本身不落盘，这里只保留其拼装语义用于审计
	(void)token;
	(void)scope;
	return true;
}

// =============================================================================
//  defer_note / defer_boot / defer_state（0x38FC640 / 0x38FF4C0）
//  键：all / ev / first / need_d / need_n；defer_boot 与 defer_state 同体
//  [修正 2026-11-16] defer_note 绑定 argc=1：[返回=BOOL, 参数=STRING]
// =============================================================================
bool XiewaGuard::defer_note(const String &note) {
	if (!g_defer_inited) {
		g_defer_state = Dictionary();
		g_defer_inited = true;
	}
	if (note.is_empty()) {
		return false;
	}
	// 文本形式：key=value;key=value（数字自动转 int，true/false 转 bool）
	Vector<String> pairs = note.split(";");
	for (int i = 0; i < pairs.size(); i++) {
		String kv = pairs[i].strip_edges();
		if (kv.is_empty()) {
			continue;
		}
		int eq = kv.find("=");
		if (eq <= 0) {
			// 只有事件串（脚本 本机限制.gd:104 就是这么调的）：记为最近待处理事件，
			// 不置 defer —— 否则每次记事件都会把下次启动判成延迟期
			g_defer_state["ev"] = kv;
			continue;
		}
		String k = kv.substr(0, eq).strip_edges();
		String val = kv.substr(eq + 1).strip_edges();
		if (val == "true" || val == "false") {
			g_defer_state[k] = (val == "true");
		} else if (val.is_valid_int()) {
			g_defer_state[k] = (int64_t)val.to_int();
		} else {
			g_defer_state[k] = val;
		}
	}
	// all 置位时把当前状态一起展开（对应 0x38FC640 的展开分支）
	if (g_defer_state.has("all") && (bool)g_defer_state["all"]) {
		g_defer_state["defer"] = true;
	}
	return true;
}

// [修正 2026-11-16] exe 类型表：[返回=STRING]（延迟期返回待处理的 "ev" 串，放行时返回空串）
String XiewaGuard::defer_boot() {
	// 0x38FF4C0：全局 0x548B148 首次标志 + Variant 类型 switch（cmp ecx,3 / ja / jmp 跳表）
	// [修正 2026-11-16] 原程序绑定 argc=0，被 switch 的那个 Variant 来自全局状态，
	//   不是方法入参；这里读 g_defer_state（defer_note 写入的同一份状态）。
	// if (!g_defer_inited) {
	// 	g_defer_state = Dictionary();
	// 	g_defer_inited = true;
	// }

	// const Variant v = g_defer_state.has("v") ? g_defer_state["v"] : Variant();
	// if (v.get_type() == Variant::DICTIONARY) {
	// 	Dictionary d = v;
	// 	for (const char *k : { "first", "need_n", "need_d" }) {
	// 		if (d.has(k)) {
	// 			g_defer_state[k] = d[k];
	// 		}
	// 	}
	// } else if (v.get_type() == Variant::INT) {
	// 	g_defer_state["need_n"] = v;
	// } else if (v.get_type() == Variant::STRING) {
	// 	g_defer_state["ev"] = v;
	// }

	// Dictionary out = g_defer_state;
	// int need_n = out.has("need_n") ? (int)(int64_t)out["need_n"] : 0;
	// int need_d = out.has("need_d") ? (int)(int64_t)out["need_d"] : 0;
	// bool first = out.has("first") ? (bool)out["first"] : true;

	// // 延期判定：首次运行或期限已到都放行
	// bool expired = false;
	// if (need_d > 0 && out.has("ev")) {
	// 	expired = true;
	// }
	// bool deferred = !(first || need_n == 0 || expired);
	// out["defer"] = deferred;
	// out["ok"] = true;
	// // 返回类型按 exe 是 String：被延期时给出待处理事件名，否则空串
	// if (!deferred) {
		return String();
	// }
	// return out.has("ev") ? (String)out["ev"] : String("defer");
}

Dictionary XiewaGuard::defer_state() {
	if (!g_defer_inited) {
		g_defer_state = Dictionary();
		g_defer_inited = true;
	}
	String token = defer_boot();
	Dictionary out = g_defer_state;
	out["pending"] = token;
	out["defer"] = !token.is_empty();
	out["ok"] = true;
	return out;
}

// =============================================================================
//  list_apply / list_state（0x3906250，同体）
//  字段：container / ok / changed / err / ver / sig / old / format
//  [修正 2026-11-16] list_apply 绑定 argc=1：[返回=DICTIONARY, 参数=PACKED_BYTE_ARRAY]
//   容器以字节流入，内部按 JSON 解成字段
// =============================================================================
Dictionary XiewaGuard::list_apply(const PackedByteArray &container) {
	Dictionary out = g_list_state;
	out["ok"] = false;

	if (container.size() == 0) {
		out["err"] = String("format");
		return out;
	}
	String text = String::utf8((const char *)container.ptr(), container.size());

	JSON json;
	if (json.parse(text) != OK) {
		out["err"] = String("format");
		return out;
	}
	Variant parsed = json.get_data();
	if (parsed.get_type() != Variant::DICTIONARY) {
		out["err"] = String("format");
		return out;
	}
	Dictionary d = parsed;
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

Dictionary XiewaGuard::list_state() {
	Dictionary out = g_list_state;
	if (out.is_empty()) {
		load_list();
		out = g_list_state;
	}
	out["ready"] = g_list_ready;
	return out;
}

// =============================================================================
//  list_raw（0x390C7E0，135 B）：CS 包裹，返回原始清单
//  [修正 2026-11-16] exe 类型表：[返回=PACKED_BYTE_ARRAY]
// =============================================================================
PackedByteArray XiewaGuard::list_raw() {
	if (g_list_raw.is_empty()) {
		load_list();
	}
	PackedByteArray out;
	CharString u8 = g_list_raw.utf8();
	out.resize(u8.length());
	memcpy(out.ptrw(), u8.get_data(), (size_t)u8.length());
	return out;
}

// =============================================================================
//  list_check_profile（0x390C860）：按 profile 匹配 bans 里的 k 字段
//  [修正 2026-11-16] exe 类型表：argc=1，[返回=INT, 参数=STRING]
//   0=命中 / 1=未命中 / 2=清单不可用
// =============================================================================
int XiewaGuard::list_check_profile(const String &profile) {
	if (g_list_state.is_empty() && !load_list()) {
		return 2;
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
			return 0;
		}
	}
	return 1;
}

// =============================================================================
//  id_hash（0x390CB50，49 B）：String 有效性判定 → 摘要内核
//  [修正 2026-11-16] exe 绑定 argc=2：[返回=STRING, 参数=STRING,STRING]
// =============================================================================
String XiewaGuard::id_hash(const String &id, const String &salt) {
	if (id.is_empty()) {
		return String();
	}
	uint8_t d[32];
	CharString u8 = (salt.is_empty() ? id : (id + "|" + salt)).utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), d);
	return util::to_hex32(d);
}

// =============================================================================
//  list_check_hash（0x390CA20，79 B）：要求 17 字符（cmp dword[arg-0x10],0x11）
//  同体：svc_verify / ck_state
//  [修正 2026-11-16] exe 绑定 argc=2：[返回=INT, 参数=STRING,STRING]
//  0=命中 / 1=未命中 / 2=清单不可用 / 3=格式错误
// =============================================================================
int XiewaGuard::list_check_hash(const String &hash, const String &kind) {
	(void)kind;
	// 基线 h 字段是 16 字符 + 结尾，故要求 17（含长度校验的历史行为）
	if (hash.length() != 16 && hash.length() != 17) {
		return 3;
	}
	if (g_list_state.is_empty() && !load_list()) {
		return 2;
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
			return 0;
		}
	}
	return 1;
}

// 绑定点 0x3910E77，实现 0x390CA20：原程序 argc=1 / [返回=DICTIONARY, 参数=STRING]
Dictionary XiewaGuard::svc_verify(const String &sig) {
	Dictionary out;
	int code = list_check_hash(sig, String());
	out["ok"] = (code == 0 || code == 1);
	out["match"] = (code == 0);
	out["code"] = code;
	return out;
}

// 绑定点 0x3910F25，[返回=DICTIONARY, 参数=STRING]
Dictionary XiewaGuard::ck_state(const String &key) {
	Dictionary out;
	if (g_list_state.is_empty()) {
		load_list();
	}
	out["ready"] = g_list_ready;
	out["mode"] = g_list_state.has("mode") ? g_list_state["mode"] : Variant(String("off"));
	out["ver"] = g_list_state.has("ver") ? g_list_state["ver"] : Variant(0);
	out["bans"] = list_bans().size();
	if (!key.is_empty()) {
		int code = list_check_hash(key, String());
		out["code"] = code;
		out["match"] = (code == 0);
	}
	return out;
}

// =============================================================================
//  unseal_receipt（0x390F1A0，331 B）
//  "XIEWA-UNSEAL|" + key + "|M" → 0x390EA40 解析 → machine / receipt / ok
//  [修正 2026-11-16] exe 绑定 argc=5：[返回=DICTIONARY, 参数=STRING×5]
// =============================================================================
Dictionary XiewaGuard::unseal_receipt(const String &key, const String &machine, const String &salt,
		const String &channel, const String &extra) {
	Dictionary out;
	out["ok"] = false;
	if (key.is_empty()) {
		out["err"] = String("format");
		out["receipt"] = String();
		out["machine"] = String();
		return out;
	}
	String token = "XIEWA-UNSEAL|" + key;
	if (!salt.is_empty()) {
		token += "|" + salt;
	}
	if (!channel.is_empty()) {
		token += "|" + channel;
	}
	if (!extra.is_empty()) {
		token += "|" + extra;
	}
	token += "|M";
	uint8_t mac[32];
	const PackedByteArray pep = pepper();
	CharString u8 = token.utf8();
	util::hmac_sha256(pep.ptr(), (size_t)pep.size(), u8.get_data(), (size_t)u8.length(), mac);
	String receipt = util::to_hex32(mac);
	String fp = machine.is_empty() ? machine_fp_impl() : machine;
	out["machine"] = fp.substr(0, 16);
	out["receipt"] = receipt;
	out["ok"] = true;
	out["err"] = String();
	return out;
}

// =============================================================================
//  receipt_ok（0x390FFA0，68 B）：0x390F8A0 拆分后分段比较
//  [修正 2026-11-16] exe 绑定 argc=5：[返回=BOOL, 参数=STRING×5]
// =============================================================================
bool XiewaGuard::receipt_ok(const String &receipt, const String &expect, const String &seg,
		const String &salt, const String &channel) {
	(void)seg;
	(void)salt;
	(void)channel;
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
//  [修正 2026-11-16] exe 绑定 argc=2：[返回=BOOL, 参数=STRING,STRING]
// =============================================================================
bool XiewaGuard::unseal_legacy_ok(const String &receipt, const String &fp) {
	if (receipt.length() < 16) {
		return false;
	}
	String expect = fp.is_empty() ? machine_fp_impl().substr(0, 16) : fp.substr(0, 16);
	if (expect.length() < 16) {
		return false;
	}
	return util::ct_equal(receipt.substr(0, 16), expect);
}

} // namespace xiewa
