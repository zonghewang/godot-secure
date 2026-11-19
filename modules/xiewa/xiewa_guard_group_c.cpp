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
// 封印自愈需要从 native 侧拿到场景树，再去调 /root/LocalSaveManager 的账户段接口。
// 注意 Godot 4.6 已经把 get_main_loop 从 Engine 移到 OS（core/os/os.h:232），
// include "core/engine.h" 这条路在本版本不存在（engine.h 实际在 core/config/engine.h）。
#include "scene/main/node.h"
#include "scene/main/scene_tree.h"
#include "scene/main/window.h"

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

// 官方 本机限制.machine_seal_all() 的判据只有两条：
//   ① machine_all() 为真（整机名单里有记录）
//   ② ev 里存在任意一个不等于 "X7L" 的码
// 只要两条同时成立，数值守卫 的 修改器痕迹() 就塞进 "M8"，随后以 x8 封档。
// 早先这里把 S1 / M1 / U3 当"警告码"留着，可它们都不等于 X7L —— 等于亲手把 M8 打开。
// 现在一律归一成 "X7L"：整机名单只表达"警告过一次"，不再承载任何能触发封档的码。
String sanitize_ev_codes(const String &ev) {
	if (ev.strip_edges().is_empty()) {
		return String();
	}
	return String("X7L");
}

// 自编版自己的记账目录（放在 ombrel_cache 下的 local 子目录）。
// 官方只认 ombrel_cache 根部的通道文件，不会把这里的记录当成整机名单。
String devlimit_dir() {
	return cache_root() + "/local";
}

// -----------------------------------------------------------------------------
// 诊断日志
// release 版 XW_DEBUG_PRINT 是空语句，print_line 调不起来，出问题只能靠落盘看。
// 只记"状态发生变化"的少量事件（清理命中、自愈写入、首次状态快照），不会狂写。
// 落点：%APPDATA%\Ombrel\rt\xiewa_module.log（与游戏自己的日志同目录，方便一起发）
// -----------------------------------------------------------------------------
uint64_t now_ms() {
	OS *os = OS::get_singleton();
	return os != nullptr ? os->get_ticks_msec() : 0;
}

String diag_log_path() {
#ifdef WINDOWS_ENABLED
	String base = OS::get_singleton()->get_environment("APPDATA");
	if (base.is_empty()) {
		return String();
	}
	return base + "/Ombrel/rt/xiewa_module.log";
#else
	return String();
#endif
}

String now_stamp() {
	OS::DateTime t = OS::get_singleton()->get_datetime();
	auto p2 = [](int v) -> String { return v < 10 ? String("0") + String::num_int64(v) : String::num_int64(v); };
	return String::num_int64(t.year) + "-" + p2(t.month) + "-" + p2(t.day) + " " +
			p2(t.hour) + ":" + p2(t.minute) + ":" + p2(t.second);
}

// 追加一行。FileAccess 没有 APPEND 模式，只能"读旧 + 重写"，
// 所以设了 256 KB 上限，超出时只保留最后一半，避免无限膨胀。
void diag(const String &line) {
	const String path = diag_log_path();
	if (path.is_empty() || !DirAccess::dir_exists_absolute(path.get_base_dir())) {
		return;
	}
	String old;
	if (FileAccess::exists(path)) {
		Ref<FileAccess> rf = FileAccess::open(path, FileAccess::READ);
		if (rf.is_valid()) {
			old = rf->get_as_text();
			if (old.length() > 262144) {
				old = old.substr(old.length() - 131072);
			}
		}
	}
	Ref<FileAccess> wf = FileAccess::open(path, FileAccess::WRITE);
	if (wf.is_valid()) {
		wf->store_string(old + "[" + now_stamp() + "] " + line + "\n");
		wf->flush();
	}
}

// 官方口径的"整机名单"记录有两个落点，同名：
//   ① 注册表 HKCU\Software\<vendor>\Cache 下的值（REG_BINARY）
//   ② %LOCALAPPDATA%\<vendor>\cache 与 %PROGRAMDATA%\<vendor>\cache 下的 <name>.idx
// 名字都由 name2 生成，形如 "xw2-" + 12 位十六进制；内容以 "XWD3" 魔数开头
// （XWD3 就是官方 _DUAL_MAGIC3 = 0x33445758，所以不能只凭魔数判断 —— 存档/账本
//  记录也用同一个魔数，靠 "xw2-" 名字前缀区分才不会误删存档）。
//
// 为什么要清：官方 本机限制.machine_seal_all() 只看"整机名单是否存在 + ev 是否非 X7L"。
// 只要这条记录在，官方版每次启动都会以 M8 封档。
int purge_whole_machine_marks(const String &vendor_name) {
	int removed = 0;
#ifdef WINDOWS_ENABLED
	// 键名与值名都是 ASCII，直接用 ANSI 版 API，省掉宽字符转换
	String sub = String("Software\\") + vendor_name + "\\Cache";
	HKEY key = nullptr;
	if (RegOpenKeyExA(HKEY_CURRENT_USER, sub.utf8().get_data(), 0, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS) {
		Vector<String> hits;
		DWORD index = 0;
		char value_name[512];
		DWORD value_len = 0;
		DWORD value_type = 0;
		BYTE data[2048];
		DWORD data_len = 0;
		while (true) {
			value_len = 512;
			data_len = sizeof(data);
			LONG rc = RegEnumValueA(key, index, value_name, &value_len, nullptr, &value_type, data, &data_len);
			if (rc != ERROR_SUCCESS) {
				break;
			}
			index++;
			String name = String(value_name);
			if (!name.begins_with("xw2-")) {
				continue;
			}
			if (value_type != REG_BINARY || data_len < 4) {
				continue;
			}
			// 前 4 字节是不是 "XWD3"
			if (!(data[0] == 'X' && data[1] == 'W' && data[2] == 'D' && data[3] == '3')) {
				continue;
			}
			hits.push_back(name);
		}
		for (int i = 0; i < hits.size(); i++) {
			RegDeleteValueA(key, hits[i].utf8().get_data());
			removed++;
		}
		RegCloseKey(key);
	}
#endif
	// 同步删掉两个缓存目录下同名 .idx（注册表没了、文件还在，官方仍会读到）
	const String dirs[2] = {
		String(OS::get_singleton()->get_environment("LOCALAPPDATA")) + "/" + vendor_name + "/cache",
		String(OS::get_singleton()->get_environment("PROGRAMDATA")) + "/" + vendor_name + "/cache",
	};
	for (int d = 0; d < 2; d++) {
		if (dirs[d].length() <= 3 || !DirAccess::dir_exists_absolute(dirs[d])) {
			continue;
		}
		Ref<DirAccess> da = DirAccess::open(dirs[d]);
		if (da.is_null()) {
			continue;
		}
		da->list_dir_begin();
		String f = da->get_next();
		while (!f.is_empty()) {
			if (!da->current_is_dir() && f.begins_with("xw2-") && f.ends_with(".idx")) {
				DirAccess::remove_absolute(dirs[d].path_join(f));
				removed++;
			}
			f = da->get_next();
		}
		da->list_dir_end();
	}
	return removed;
}

// 清理自编版自己留下的记账文件（devlimit* / devheal* / unseal*）。
// 为什么要清：官方 EXE 的 native 与这里共用 cache_root()/local 这个目录，
// 任何一条 devlimit*.json 都会让官方 devlimit_state()["all"] 变 true；
// 一旦 all=true 再加上一个非 X7L 的码，官方就 M8 封档。所以这份"遗留"必须清掉。
int purge_own_bookkeeping() {
	int removed = 0;
	const String dirs[2] = { devlimit_dir(), cache_root() };
	for (int d = 0; d < 2; d++) {
		if (dirs[d].length() <= 3 || !DirAccess::dir_exists_absolute(dirs[d])) {
			continue;
		}
		Ref<DirAccess> da = DirAccess::open(dirs[d]);
		if (da.is_null()) {
			continue;
		}
		da->list_dir_begin();
		String f = da->get_next();
		while (!f.is_empty()) {
			if (!da->current_is_dir() && (f.begins_with("devlimit") || f.begins_with("devheal") || f.begins_with("unseal"))) {
				if (DirAccess::remove_absolute(dirs[d].path_join(f)) == OK) {
					removed++;
				}
			}
			f = da->get_next();
		}
		da->list_dir_end();
	}
	return removed;
}

// -----------------------------------------------------------------------------
// 封印自愈：让"用自编版跑过一次"之后，官方原版 EXE 也能打开同一份存档
//
// 背景：官方把封档信息写进存档的账号段 anti_ce 里（sealed / seal_type / at /
// nonce / appeal / x7 / x8 …）。这份状态一旦写进去，即使把整机名单记录清空，
// 已封印也不会自己消失 —— 官方每次启动读档都会继续判"本账号已封禁"。
//
// 为什么必须走脚本层写：账号段是加密 + 带完整性签名的，native 侧直接改 save.dat
// 会被官方判成"存档与游戏封存的记录对不上"。所以这里只做管道的事 —— 通过
// /root/LocalSaveManager 的 get_account_section / set_account_section 走游戏自己的
// 写档流程，存档按原格式重新签名，官方读这份档就是一致的。
//
// 为什么必须连 unsealed_at / ur 一起清：官方 数值守卫._解封无回执()（:374-382）的判据是
//   "unsealed_at 非空 且 未封印 且 回执验不过" → 命中就给 U3，
// 而 U3 属于 LOCAL_ONLY_CODES → 立刻再封本档。所以不能留半点"解封过"的痕迹，
// 只能把整组封印字段整体回到"从未封印"的样子（这也是官方 解封() 之外唯一自洽的形态）。
// 次数上限是历史上最大的坑：开机早期 devlimit_state() 会被 外挂开机检查 / 开机扫档案 调用，
// 那时档案还没打开（has_active_profile 为 false），旧实现"最多 6 次尝试"会在一瞬间被白白耗光，
// 等真正读档、真正需要清封印时已经彻底放弃 —— 这就是"官方封完、自编再启动仍然封着"的直接原因。
// 现在：不设上限、按时间节流、前两次延后写之后改立即写，并且每次调用都重新读账号段，
// 只有读到干净状态才停手（天然带写后校验）。
bool heal_account_seal(bool p_immediate, int p_attempt) {
	MainLoop *ml = OS::get_singleton()->get_main_loop();
	SceneTree *tree = Object::cast_to<SceneTree>(ml);
	if (tree == nullptr) {
		return false;
	}
	Window *root_window = tree->get_root();
	if (root_window == nullptr) {
		return false;
	}
	Node *lsm = root_window->get_node_or_null(NodePath("LocalSaveManager"));
	if (lsm == nullptr || !lsm->has_method("get_account_section") || !lsm->has_method("set_account_section")) {
		return false;
	}
	bool changed = false;

	// ① 申诉上下文。数值守卫.已封印():1193 只要 has_guard_appeal_context() 为真就直接返回 true，
	//    光清账号段不够，这层内存上下文同样会让界面继续弹封印页。
	if (lsm->has_method("has_guard_appeal_context")) {
		Variant hv = lsm->call("has_guard_appeal_context");
		if (hv.get_type() == Variant::BOOL && bool(hv) && lsm->has_method("clear_guard_appeal_context")) {
			lsm->call("clear_guard_appeal_context");
			changed = true;
			diag("[heal] 清除申诉上下文 _guard_appeal_context");
		}
	}

	// ② 账号段：必须档案真的打开过，否则会把空段写回去
	if (!lsm->has_method("has_active_profile")) {
		return changed;
	}
	Variant active_v = lsm->call("has_active_profile");
	if (active_v.get_type() != Variant::BOOL || !bool(active_v)) {
		return changed;
	}

	Variant cur_v = lsm->call("get_account_section", String("anti_ce"), Variant(Dictionary()));
	if (cur_v.get_type() != Variant::DICTIONARY) {
		return changed;
	}
	Dictionary ac = cur_v;

	const bool has_seal = bool(ac.get("sealed", false)) || ac.has("seal_type") || ac.has("appeal") ||
			ac.has("unsealed_at") || ac.has("ur") || ac.has("x7") || ac.has("x8") || ac.has("reason");
	// 除了"已封印"，还有三类"会被判封"的残留，必须一起清：
	//   client_mod        —— 客户端校验（globals/客户端校验.gd：可执行哈希不在官方白名单 → "B"）
	//                        warned>=1 的**下一次**启动会直接 _置封印(category="client_mod")。
	//                        自编 exe 的哈希永远不在官方白名单，这条路径每启动一次就攒一次，
	//                        不清就等于"第二/第三次启动必封"。
	//   closes/tool_hits  —— 累计"数值被修改 / 工具痕迹"次数，攒够阈值就 数值守卫:1174 封档。
	//   tamper_pending    —— 待处理的篡改标记。
	const bool has_client = ac.has("client_mod") || (int)ac.get("client_mod_warned", 0) != 0;
	const bool has_counters = (int)ac.get("closes", 0) != 0 || (int)ac.get("tool_hits", 0) != 0 ||
			(int)ac.get("tamper_pending", 0) != 0 || bool(ac.get("repair_pending", false));
	if (!has_seal && !has_client && !has_counters) {
		return changed; // 已经是干净状态
	}

	// 只清"会被判封"的字段；pid / ob / entry_audit / audit_r2 / nonce 等审计字段原样保留
	ac["sealed"] = false;
	ac["closes"] = 0;
	ac["tool_hits"] = 0;
	ac["client_mod_warned"] = 0;
	ac["tamper_pending"] = 0;
	ac["repair_pending"] = false;
	const char *drop[] = {
		"seal_type", "reason", "appeal", "at", "unsealed_at", "ur", "x7", "x8",
		"closes_base", "tool_hits_base", "close_at", "tool_hit_at", "client_mod", "tamper"
	};
	for (const char *k : drop) {
		ac.erase(String(k));
	}

	const String keys = String(has_seal ? "封印" : "") + String(has_client ? "+客户端警告" : "") +
			String(has_counters ? "+累计计数" : "");

	if (p_immediate) {
		lsm->call("set_account_section", String("anti_ce"), Variant(ac), Variant(true));
	} else {
		// 延后 + 不强制 flush：触发点通常落在读档流程里，立刻落盘会和正在进行的
		// 存档提交互相踩（历史上"写档耗时 / 未提交本次存档"就是这么来的）；
		// 不强制 flush 时只是把段标记为脏，随正常存档周期写下去，IO 也不会爆。
		lsm->call_deferred("set_account_section", String("anti_ce"), Variant(ac), Variant(false));
	}
	changed = true;
	if (p_attempt <= 10 || (p_attempt % 20) == 0) {
		diag(String("[heal] 第") + String::num_int64(p_attempt) + "次清理账号段封印字段 [" + keys + "]" +
				(p_immediate ? "（立即落盘）" : "（延后落盘）"));
	}
	return changed;
}

// 节流调用点：devlimit_state() / devlimit_mark() / machine_fp() 都会调。
// 前 40 次 250ms 一次（覆盖"开机 → 真正读档"这一段），之后退到 2 秒一次，永不停。
// 注意：档案没打开时这里什么也不做（has_active_profile 为 false），不会浪费次数。
void maybe_heal_account_seal() {
	static int attempt = 0;
	static uint64_t last_ms = 0;
	uint64_t t = now_ms();
	uint64_t gap = attempt < 40 ? 250 : 2000;
	if (last_ms != 0 && t - last_ms < gap) {
		return;
	}
	last_ms = t;
	attempt++;
	// 头两次先延后（避开读档流程），第 3~8 次强制落盘（覆盖"刚封完就关档"的场景），
	// 之后退成延后脏写，靠正常存档周期写下去，避免 250ms 一次的 IO 抖动。
	heal_account_seal(attempt > 2 && attempt <= 8, attempt);
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
	// 数值守卫.修改器痕迹() 每次开档都会先问 bridge_check（has_v3 分支），
	// 这个点是"档案数据已载入、封印判定之前"的时机，适合推进一次封印自愈。
	maybe_heal_account_seal();
	(void)flags;
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
	// 数值守卫 开机扫档案(:498) / 联网认证(:221) 都会先问 machine_fp，
	// 在这里顺带推进一次封印自愈，让自愈的触发点早于任何 M8 判定。
	maybe_heal_account_seal();
	return machine_fp_impl();
}

Dictionary XiewaGuard::devlimit_state() {
	Dictionary out;
	const String fp = machine_fp_impl();
	out["fp"] = fp;

	static uint64_t last_purge_ms = 0;
	static uint64_t last_diag_ms = 0;
	static bool diag_inited = false;
	uint64_t t = now_ms();

	// ① 周期性清理官方口径的整机名单（注册表 xw2-* + XWD3、两个 cache 目录下 xw2-*.idx）。
	//    旧实现"每进程只清一次"，二次启动/二次封印后就再也不管了；现在 1s 节流常驻。
	int removed = 0;
	if (last_purge_ms == 0 || t - last_purge_ms > 1000) {
		last_purge_ms = t;
		removed = purge_whole_machine_marks(vendor()) + purge_own_bookkeeping();
		if (removed > 0) {
			diag(String("[purge] 清理遗留整机名单 / 记账文件 ") + String::num_int64(removed) + " 条");
		}
	}

	// ② 账号段封印自愈：节流常驻、无次数上限，档案一打开就会重试到读不到封印字段为止
	maybe_heal_account_seal();

	// ③ 固定返回"整机无限制"。这就是 M8 的开关本身：
	//    官方 本机限制.gd machine_all() = enabled() && devlimit_state()["all"]；
	//    machine_seal_all() = machine_all() && ev 里存在 != "X7L" 的码 → 数值守卫 记 M8 → x8 封档。
	//    旧实现把 all 算成"自己目录里有几条 devlimit*.json"，等于自编版自己记一条事件
	//    就把 M8 开关打开（完全自伤，与官方是否在线无关）。这里 all 恒 false、ev 恒空，
	//    脚本层 machine_all() 永远为假，M8 在自编版这一侧从源头不可能成立。
	//    脚本契约仍完整给出：本机限制.gd 取 all / ev / first / need_d / need_n 五键。
	out["records"] = Array();
	out["count"] = 0;
	out["all"] = false;
	out["ev"] = String();
	out["first"] = true; // true = 尚无任何限制记录
	out["need_d"] = 0;
	out["need_n"] = 0;
	out["ok"] = true;

	if (!diag_inited || t - last_diag_ms > 5000) {
		diag_inited = true;
		last_diag_ms = t;
		diag(String("[state] all=false ev=\"\" fp=") + fp + (removed > 0 ? " (刚清过名单)" : ""));
	}
	return out;
}

// =============================================================================
//  devlimit_mark（0x38FBE00）：写 ev / at / fp 三个字段
//  [修正 2026-11-16] exe 类型表：argc=1，[返回=BOOL, 参数=STRING]
// =============================================================================
bool XiewaGuard::devlimit_mark(const String &event) {
	// 关键改动：这里**不再落任何文件**。
	// 自编模块与官方 EXE 共用同一套 native 契约、同一个路径：
	//   cache_root()   = %APPDATA%\Ombrel\rt\ombrel_cache
	//   devlimit_dir() = cache_root()/local
	// 旧实现每记一次事件就在 devlimit_dir() 里写一条 devlimit.json，于是
	//   自编版 devlimit_state()["all"] = "有记录" → true
	//   **官方 EXE 里同一份 native 逻辑读同一目录 → all 也是 true**
	// 这时只要 ev 里有一个不等于 X7L 的码，官方就判 machine_seal_all() → M8 → x8 封档。
	// 换句话说：自编版留的记账文件本身就是把刀递给官方。现在只写诊断日志，
	// 同时把本地遗留的 devlimit* / devheal* / unseal* 记账文件删掉，
	// 让官方读到的"整机名单"永远是空的（all=false）。
	if (event.strip_edges().is_empty()) {
		return false;
	}
	const String ev = sanitize_ev_codes(event);
	diag(String("[mark] 记事件已降级为日志（不落盘） 原始=") + event + " 归一=" + (ev.is_empty() ? String("空") : ev));

	static uint64_t last_ms = 0;
	uint64_t t = now_ms();
	if (last_ms == 0 || t - last_ms > 200) {
		last_ms = t;
		int removed = purge_own_bookkeeping();
		if (removed > 0) {
			diag(String("[mark] 删除遗留记账文件 ") + String::num_int64(removed) + " 条");
		}
	}

	// 刚记过事件，顺手把可能残留的封印状态再清一遍（mark 往往发生在 M8 判定之后）
	maybe_heal_account_seal();
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
	// 只清理"限制记录"类文件，不碰同目录的 0.bin / *.idx / snap\ ——
	// 早前删整目录会导致"存档记录已被清理，无法读取"。
	const String scan_dirs[2] = { cache_root(), devlimit_dir() };
	for (int d = 0; d < 2; d++) {
		String dir = scan_dirs[d];
		if (!DirAccess::dir_exists_absolute(dir)) {
			continue;
		}
		Ref<DirAccess> da = DirAccess::open(dir);
		if (da.is_null()) {
			continue;
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
	}

	// 官方口径的整机名单记录（"xw2-" 前缀 + XWD3 内容）一并清掉
	purge_whole_machine_marks(vendor());
	// 解封/解除这条路径上也把账号段的封印状态清干净（否则官方版还会接着判已封印）
	heal_account_seal(true, 1);
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
