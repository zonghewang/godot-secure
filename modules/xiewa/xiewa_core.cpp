// =============================================================================
//  xiewa_core.cpp —— XiewaCore 的 6 个 core_* 方法真实实现
//
//  实现地址：
//    core_version        0x3413190（`mov eax,7; ret`）
//    core_selftest       0x391A180（SHA-256 空串自检）
//    core_sha256_hex     0x34131B0（String → SHA-256 → 小写 hex）
//    core_shell          0x3413300（返回 6 字符字面量 ".fDept"）
//    core_rpc            0x3413340（信封分发：rng_test_seed / rules_load_signed / snap_*）
//    core_rules_selftest 0x3927060（HMAC-SHA256 RFC 4231 TC2 自检）
//
//  ---------------------------------------------------------------------------
//  [2026-11-18] core_rpc 按 0x3413340 的真实分发重写
//
//  0x3413340 取 fn 后只有三条路：
//    1) len(fn)==13（0xD）且 == "rng_test_seed"  → 取 "qa"，非 qa 返回 not_qa
//    2) len(fn)==17（0x11）且 == "rules_load_signed" → 取 "body"/"sig" 走验签
//    3) fn.begins_with("snap_")（9 或 11 字符）→ 0x38F8540("snap-v1") 派生密钥
//       + 0x38F7B60(2) bridge 检查 + 0x3928960 快照状态机
//    其它 → {"ok":0,"err":"fn"}
//
//  0x3928960 的 fn 分发（精确）：
//    9 字符：snap_seal → 0x3928FA4；snap_open → 0x3928C89；否则 err:fn
//    11 字符：snap_rebind → 0x392901E；snap_status → 0x39290BD；否则 err:fn
//
//  ---------------------------------------------------------------------------
//  snap seal 的真实字节格式（0x392CE70 编码 / 0x392CFD0 解码）
//
//    编码 0x392CE70(dst, key, bind, payload)：
//        msg  = "xwsnap1\n" + bind + "\n" + payload        （0x392CE89 movabs 0xa3170616e737778）
//        raw  = HMAC-SHA256(key, msg)                        （0x391BD00，32 字节）
//        hex  = lower_hex(raw)                               （0x392CF40 resize 0x40 + "0123456789abcdef"）
//    拼装 0x3929C77 起： "XS1." (0x2E315358) + hex + "." + payload
//    解码 0x392CFD0：要求 len>=70、[0..3]=="XS1."、[68]=='.'
//        → out_a = seal[4..67]（64 hex 原样字符串）、out_b = seal[69:]
//    校验 0x3928DE4 → 0x3919A90(String 逐字节异或比较)：重算 hex 与 seal 里的 hex 相等
//
//  key 派生 0x38F8540(label) → 0x38F12E0(HMAC-SHA256)：
//        str = "xw3|" + label                                （0x38F857C movabs 0x7c337778 = "xw3|"）
//        mat[i] = C[(11+7i)&31] ^ B[(3+5i)&31] ^ G[i]
//                 ^ (uint8)(A[(9+11i)&31] * 45 + (0x5A + 23i))
//        key = HMAC-SHA256(mat, str)
//        （A@0x51F6500 / B@0x51F6520 / C@0x51F6540 / G@0x20AA7D0，各 32 字节）
// =============================================================================

#include "xiewa_core.h"
#include "xiewa_guard.h"
#include "xiewa_util.h"

#include "core/config/engine.h"
#include "core/object/ref_counted.h"
#include "core/os/main_loop.h"
#include "core/string/ustring.h"
#include "core/variant/dictionary.h"
#include "core/variant/variant.h"
#include "scene/main/node.h"
#include "scene/main/scene_tree.h"
#include "scene/main/window.h"

#if __has_include("core/variant/json.h")
#include "core/variant/json.h"
#else
#include "core/io/json.h"
#endif

namespace xiewa {

namespace {

const char *kSha256Empty =
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const char *kHmacTc2 =
		"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

// core_rpc 返回模板（.rdata 原串）
const char *kRpcParseFail = "{\"ok\":0,\"err\":\"parse\"}";
const char *kRpcFnFail = "{\"ok\":0,\"err\":\"fn\"}";
const char *kRpcNotQa = "{\"ok\":0,\"err\":\"not_qa\"}";
const char *kRpcSigFail = "{\"ok\":0,\"err\":\"sig\"}";
const char *kRpcBad = "{\"ok\":0,\"err\":\"bad\"}";
const char *kRpcOk = "{\"ok\":1}";

// ---------------------------------------------------------------------------
//  key 派生的四张 32 字节常量表（原版 .rdata / .text 内嵌）
// ---------------------------------------------------------------------------
const uint8_t kDeriveA[32] = {
	0x94, 0x77, 0x50, 0x29, 0xae, 0xfb, 0xf8, 0x7d,
	0xa4, 0x63, 0x01, 0x59, 0x67, 0x23, 0xaa, 0xd1,
	0x30, 0x6c, 0xe5, 0x24, 0xea, 0xdd, 0x9c, 0xa3,
	0xbf, 0x4b, 0x8d, 0x34, 0x77, 0xd5, 0x5b, 0x7a,
};
const uint8_t kDeriveB[32] = {
	0xa1, 0xf8, 0x72, 0x3e, 0xe3, 0x40, 0xc4, 0x47,
	0xd3, 0x59, 0xd2, 0xdc, 0xd2, 0x5c, 0xa2, 0x41,
	0x0f, 0x74, 0x59, 0xed, 0xe6, 0xf9, 0xea, 0xec,
	0xcb, 0x44, 0xbb, 0x76, 0xe5, 0xa8, 0xe7, 0x9e,
};
const uint8_t kDeriveC[32] = {
	0x39, 0x16, 0x01, 0x07, 0x30, 0x9b, 0x49, 0x18,
	0x76, 0x47, 0xfe, 0x05, 0xac, 0x60, 0xc2, 0xd0,
	0x7b, 0xd5, 0xfa, 0xf8, 0x75, 0xc3, 0x09, 0xb3,
	0x6f, 0x8d, 0x10, 0x77, 0xe6, 0x5f, 0xf6, 0xd8,
};
const uint8_t kDeriveG[32] = {
	0xe9, 0x83, 0xfe, 0x41, 0x80, 0xbf, 0x4d, 0x03,
	0x00, 0x00, 0x00, 0x0f, 0x85, 0xd9, 0xf9, 0xff,
	0xff, 0xe9, 0xb6, 0xfd, 0xff, 0xff, 0x48, 0x8d,
	0x05, 0x9b, 0xfd, 0xb4, 0x02, 0x48, 0x89, 0x44,
};

// ---------------------------------------------------------------------------
//  快照引擎的进程内状态（0x39290BD 读的那组全局计数）
// ---------------------------------------------------------------------------
struct SnapState {
	uint64_t sealed = 0;
	uint64_t refused = 0;
	uint64_t opened = 0;
	uint64_t open_bad = 0;
	uint64_t open_diff = 0;
	uint64_t rebind = 0;
	String last_err;
};

SnapState &snap_state() {
	// 函数内静态：进程级单例，线程安全由引擎主线程承担（原版同样是裸全局）
	static SnapState s;
	return s;
}

// 0x38F8540 + 0x38F12E0：derive(label) → 32 字节密钥
Vector<uint8_t> derive_key(const char *p_label) {
	uint8_t mat[32];
	for (int i = 0; i < 32; i++) {
		uint8_t a = kDeriveA[(9 + 11 * i) & 31];
		uint8_t b = kDeriveB[(3 + 5 * i) & 31];
		uint8_t c = kDeriveC[(11 + 7 * i) & 31];
		uint8_t g = kDeriveG[i];
		uint8_t s = (uint8_t)((uint8_t)(a * 45) + (uint8_t)(0x5A + 23 * i));
		mat[i] = (uint8_t)(c ^ b ^ g ^ s);
	}
	String seed = String("xw3|") + String(p_label);
	CharString sc = seed.utf8();
	uint8_t out[32];
	util::hmac_sha256(mat, 32, sc.get_data(), (size_t)sc.length(), out);
	Vector<uint8_t> key;
	key.resize(32);
	memcpy(key.ptrw(), out, 32);
	return key;
}

// snap-v1 的密钥只派生一次（原版 0x38F8540 每次 core_rpc 都算，这里缓存等价）
const Vector<uint8_t> &snap_key() {
	static Vector<uint8_t> k = derive_key("snap-v1");
	return k;
}

// 0x392CE70：msg = "xwsnap1\n" + bind + "\n" + payload → HMAC → 64 位小写 hex
String snap_msg_hex(const String &p_bind, const String &p_payload) {
	String msg = String("xwsnap1\n") + p_bind + String("\n") + p_payload;
	CharString mc = msg.utf8();
	uint8_t mac[32];
	const Vector<uint8_t> &k = snap_key();
	util::hmac_sha256(k.ptr(), (size_t)k.size(), mc.get_data(), (size_t)mc.length(), mac);
	return util::to_hex32(mac);
}

// 0x392CFD0：解码 "XS1." + hex64 + "." + payload
bool snap_parse_seal(const String &p_seal, String &r_hex, String &r_payload) {
	// 长度门槛 0x46（70）：4 + 64 + 1 + 至少 1 字节 payload
	if ((int)p_seal.length() < 70) {
		return false;
	}
	if (p_seal.substr(0, 4) != String("XS1.")) {
		return false;
	}
	if (p_seal.substr(68, 1) != String(".")) {
		return false;
	}
	r_hex = p_seal.substr(4, 64).to_lower();
	r_payload = p_seal.substr(69);
	return true;
}

// 0x3929C77 拼装： "XS1." + hex + "." + payload
String snap_build_seal(const String &p_bind, const String &p_payload) {
	return String("XS1.") + snap_msg_hex(p_bind, p_payload) + String(".") + p_payload;
}

// payload 里的经济段数（0x3929BDA 的 [rsp+0x140] 即 "t" 的条目数）
int snap_payload_sections(const String &p_payload) {
	Variant v = JSON::parse_string(p_payload);
	if (v.get_type() != Variant::DICTIONARY) {
		return 0;
	}
	Dictionary d = v;
	if (!d.has("t")) {
		return 0;
	}
	Variant tv = d["t"];
	if (tv.get_type() != Variant::DICTIONARY) {
		return 0;
	}
	Dictionary t = tv;
	return t.size();
}

// ---------------------------------------------------------------------------
//  账本经济计数：复刻 res://globals/经济账本.gd 的 计数() / 经济计数() 口径
//    账户段 a:  account_currencies / account_storehouse
//    角色段 cN: inventory / equipment / progression / shenshou / guardian
//  计数键形如 "a:account_currencies|cur|金币"，与官方 native payload 同构。
//  快照 payload 必须用真实计数：官方 snap_open 会拿脚本传来的 live 逐键比对，
//  塞假数据会导致官方把账本判为 diff 并封印（ac.sealed=true）。
// ---------------------------------------------------------------------------
int64_t snap_int_of(const Variant &p_v) {
	Variant::Type t = p_v.get_type();
	if (t == Variant::INT) {
		return (int64_t)p_v;
	}
	if (t == Variant::FLOAT) {
		return (int64_t)(double)p_v;
	}
	if (t == Variant::BOOL) {
		return (bool)p_v ? 1 : 0;
	}
	return 0;
}

void snap_add(Dictionary &r_out, const String &p_key, int64_t p_n) {
	if (p_n == 0) {
		return;
	}
	int64_t cur = 0;
	if (r_out.has(p_key)) {
		cur = snap_int_of(r_out[p_key]);
	}
	r_out[p_key] = cur + p_n;
}

Dictionary snap_count_section(const String &p_key, const Variant &p_value) {
	Dictionary out;
	int sep = p_key.find(":");
	if (sep < 0) {
		return out;
	}
	String section = p_key.substr(sep + 1);
	String pre = p_key + "|";
	if (section == String("account_currencies")) {
		if (p_value.get_type() == Variant::DICTIONARY) {
			Dictionary v = p_value;
			Array ks = v.keys();
			for (int i = 0; i < ks.size(); i++) {
				Variant k = ks[i];
				Variant val = v[k];
				Variant::Type vt = val.get_type();
				if (vt == Variant::INT || vt == Variant::FLOAT) {
					snap_add(out, pre + String("cur|") + String(k), snap_int_of(val));
				}
			}
		}
	} else if (section == String("progression")) {
		if (p_value.get_type() == Variant::DICTIONARY) {
			Dictionary pd = p_value;
			if (pd.has("kungfu_bean")) {
				snap_add(out, pre + String("cur|bean"), snap_int_of(pd["kungfu_bean"]));
			}
			if (pd.has("level")) {
				snap_add(out, pre + String("lv|level"), snap_int_of(pd["level"]));
			}
			if (pd.has("exp")) {
				snap_add(out, pre + String("exp|cur"), snap_int_of(pd["exp"]));
			}
			if (pd.has("total_exp")) {
				snap_add(out, pre + String("exp|total"), snap_int_of(pd["total_exp"]));
			}
		}
	} else if (section == String("inventory")) {
		if (p_value.get_type() == Variant::DICTIONARY) {
			Dictionary inv = p_value;
			const char *arr_keys[3] = { "equipment", "items", "materials" };
			for (int a = 0; a < 3; a++) {
				String ak = String(arr_keys[a]);
				if (!inv.has(ak) || inv[ak].get_type() != Variant::ARRAY) {
					continue;
				}
				Array ea = inv[ak];
				for (int i = 0; i < ea.size(); i++) {
					if (ea[i].get_type() != Variant::DICTIONARY) {
						continue;
					}
					Dictionary ed = ea[i];
					int64_t id = ed.has("id") ? snap_int_of(ed["id"]) : 0;
					int64_t cnt = (ak == String("equipment")) ? 1 : (ed.has("count") ? snap_int_of(ed["count"]) : 1);
					snap_add(out, pre + ak + String("|") + itos(id), cnt);
				}
			}
		}
	} else if (section == String("equipment")) {
		if (p_value.get_type() == Variant::DICTIONARY) {
			Dictionary eq = p_value;
			Array slots = eq.keys();
			for (int i = 0; i < slots.size(); i++) {
				Variant e = eq[slots[i]];
				if (e.get_type() != Variant::DICTIONARY) {
					continue;
				}
				Dictionary ed = e;
				int64_t id = ed.has("id") ? snap_int_of(ed["id"]) : 0;
				if (id > 0) {
					snap_add(out, pre + String("worn|") + itos(id), 1);
				}
			}
		}
	} else if (section == String("shenshou")) {
		if (p_value.get_type() == Variant::DICTIONARY) {
			Dictionary sd = p_value;
			if (sd.has("pets") && sd["pets"].get_type() == Variant::DICTIONARY) {
				Dictionary pets = sd["pets"];
				Array pids = pets.keys();
				for (int i = 0; i < pids.size(); i++) {
					snap_add(out, pre + String("pet|") + String(pids[i]), 1);
				}
			}
		}
	} else if (section == String("guardian")) {
		if (p_value.get_type() == Variant::DICTIONARY) {
			Dictionary gd = p_value;
			if (gd.has("guardians") && gd["guardians"].get_type() == Variant::DICTIONARY) {
				Dictionary gds = gd["guardians"];
				Array gids = gds.keys();
				for (int i = 0; i < gids.size(); i++) {
					snap_add(out, pre + String("gd|") + String(gids[i]), 1);
				}
			}
		}
	} else if (section == String("account_storehouse")) {
		if (p_value.get_type() == Variant::DICTIONARY) {
			Dictionary st = p_value;
			if (st.has("entries") && st["entries"].get_type() == Variant::ARRAY) {
				Array es = st["entries"];
				for (int i = 0; i < es.size(); i++) {
					if (es[i].get_type() != Variant::DICTIONARY) {
						continue;
					}
					Dictionary ed = es[i];
					String it = ed.has("item_type") ? String(ed["item_type"]) : String("item");
					int64_t id = ed.has("id") ? snap_int_of(ed["id"]) : 0;
					int64_t cnt = (it == String("equipment")) ? 1 : (ed.has("count") ? snap_int_of(ed["count"]) : 1);
					snap_add(out, pre + it + String("|") + itos(id), cnt);
				}
			}
		}
	}
	return out;
}

Dictionary snap_live_counts(const Dictionary &p_data) {
	Dictionary out;
	const char *acc_secs[2] = { "account_currencies", "account_storehouse" };
	for (int i = 0; i < 2; i++) {
		String sec = String(acc_secs[i]);
		String key = String("a:") + sec;
		out[key] = snap_count_section(key, p_data.has(sec) ? p_data[sec] : Variant());
	}
	const char *role_secs[5] = { "inventory", "equipment", "progression", "shenshou", "guardian" };
	if (p_data.has("characters") && p_data["characters"].get_type() == Variant::ARRAY) {
		Array slots = p_data["characters"];
		for (int i = 0; i < slots.size(); i++) {
			if (slots[i].get_type() != Variant::DICTIONARY) {
				continue;
			}
			Dictionary sd = slots[i];
			for (int r = 0; r < 5; r++) {
				String sec = String(role_secs[r]);
				String key = String("c") + itos(i) + String(":") + sec;
				out[key] = snap_count_section(key, sd.has(sec) ? sd[sec] : Variant());
			}
		}
	}
	return out;
}

// 当前正在写入的 _save_data（LocalSaveManager 在 _write_save_file_v4 里持有）
Dictionary snap_current_save_data() {
	Dictionary empty;
	Engine *eng = Engine::get_singleton();
	if (eng == nullptr) {
		return empty;
	}
	SceneTree *tree = Object::cast_to<SceneTree>(eng->get_main_loop());
	if (tree == nullptr) {
		return empty;
	}
	Node *root = tree->get_root();
	if (root == nullptr) {
		return empty;
	}
	Node *lsm = root->get_node_or_null(NodePath("LocalSaveManager"));
	if (lsm == nullptr) {
		return empty;
	}
	Variant v = lsm->get("_save_data");
	if (v.get_type() != Variant::DICTIONARY) {
		return empty;
	}
	Dictionary d = v;
	if (d.is_empty()) {
		return empty;
	}
	return d;
}

String snap_payload_of(const Dictionary &p_live) {
	Dictionary wrap;
	wrap["t"] = p_live;
	return JSON::stringify(wrap);
}

String snap_status_json() {
	const SnapState &s = snap_state();
	String out = String("{\"ok\":1");
	out += ",\"sealed\":" + itos((int64_t)s.sealed);
	out += ",\"refused\":" + itos((int64_t)s.refused);
	out += ",\"opened\":" + itos((int64_t)s.opened);
	out += ",\"open_bad\":" + itos((int64_t)s.open_bad);
	out += ",\"open_diff\":" + itos((int64_t)s.open_diff);
	out += ",\"rebind\":" + itos((int64_t)s.rebind);
	out += ",\"last_err\":\"" + s.last_err.json_escape() + "\"}";
	return out;
}

// snap_open（0x3928C89）：先校验 seal 的 HMAC，再把 payload 里的计数表与脚本传来的
// live 逐键比对。n>0 会被 快照拒读/快照处置 判成 diff，所以口径必须与官方一致：
// 快照与存档缺键都按 0 计，只有真的不等才算一行 diff。
String snap_open(const Dictionary &p_req) {
	String seal;
	String bind;
	if (p_req.has("seal") && p_req["seal"].get_type() == Variant::STRING) {
		seal = p_req["seal"];
	}
	if (p_req.has("bind") && p_req["bind"].get_type() == Variant::STRING) {
		bind = p_req["bind"];
	}
	String hex;
	String payload;
	if (!snap_parse_seal(seal, hex, payload)) {
		snap_state().open_bad++;
		snap_state().last_err = "parse";
		return String(kRpcBad);
	}
	if (!util::ct_equal(snap_msg_hex(bind, payload), hex)) {
		snap_state().open_bad++;
		snap_state().last_err = "bad";
		return String(kRpcBad);
	}

	Dictionary snap_t;
	Variant parsed = JSON::parse_string(payload);
	if (parsed.get_type() == Variant::DICTIONARY) {
		Dictionary pd = parsed;
		if (pd.has("t") && pd["t"].get_type() == Variant::DICTIONARY) {
			snap_t = pd["t"];
		}
	}
	Dictionary live;
	if (p_req.has("live") && p_req["live"].get_type() == Variant::DICTIONARY) {
		live = p_req["live"];
	}

	Array diff;
	int64_t n = 0;
	Array all_keys = snap_t.keys();
	Array lkeys = live.keys();
	for (int i = 0; i < lkeys.size(); i++) {
		if (!snap_t.has(lkeys[i])) {
			all_keys.push_back(lkeys[i]);
		}
	}
	for (int i = 0; i < all_keys.size(); i++) {
		Variant sk = all_keys[i];
		Dictionary a;
		Dictionary b;
		if (snap_t.has(sk) && snap_t[sk].get_type() == Variant::DICTIONARY) {
			a = snap_t[sk];
		}
		if (live.has(sk) && live[sk].get_type() == Variant::DICTIONARY) {
			b = live[sk];
		}
		Array all_sub = a.keys();
		Array bsubs = b.keys();
		for (int x = 0; x < bsubs.size(); x++) {
			if (!a.has(bsubs[x])) {
				all_sub.push_back(bsubs[x]);
			}
		}
		for (int x = 0; x < all_sub.size(); x++) {
			Variant k = all_sub[x];
			int64_t av = a.has(k) ? snap_int_of(a[k]) : 0;
			int64_t bv = b.has(k) ? snap_int_of(b[k]) : 0;
			if (av != bv) {
				Array row;
				row.push_back(String(k));
				row.push_back(av);
				row.push_back(bv);
				diff.push_back(row);
				n++;
			}
		}
	}

	if (n > 0) {
		snap_state().open_diff++;
	} else {
		snap_state().opened++;
	}
	snap_state().last_err = String();
	String out = String("{\"ok\":1,\"n\":") + itos(n) + String(",\"secs\":") + itos((int64_t)snap_t.size());
	if (n > 0) {
		out += String(",\"diff\":") + JSON::stringify(diff);
	}
	out += String("}");
	return out;
}

// snap_rebind：沿用旧 seal 的 payload，按新 bind 重算 hex（换代）
String snap_rebind(const Dictionary &p_req) {
	String seal;
	String bind;
	if (p_req.has("seal")) {
		Variant v = p_req["seal"];
		if (v.get_type() == Variant::STRING) {
			seal = v;
		}
	}
	if (p_req.has("bind")) {
		Variant v = p_req["bind"];
		if (v.get_type() == Variant::STRING) {
			bind = v;
		}
	}
	String hex;
	String payload;
	if (!snap_parse_seal(seal, hex, payload)) {
		snap_state().last_err = "parse";
		return String(kRpcBad);
	}
	String new_seal = snap_build_seal(bind, payload);
	snap_state().rebind++;
	return String("{\"ok\":1,\"n\":") + itos(snap_payload_sections(payload)) +
			",\"seal\":\"" + new_seal.json_escape() + "\"}";
}

// snap_seal：官方由 0x392C270 从引擎内部经济段现场生成 payload，脚本只传 bind。
// 因此无 payload 时必须自己从 LocalSaveManager 的 _save_data 算真实计数，
// 不能返回 nosnap —— 否则 header 里永远没有 ledger_snap，而水位记录里已有
// snap_g，读档会被 读档核对() 判成 missing（=「存档与封存的记录对不上」）。
String snap_seal(const Dictionary &p_req) {
	String bind;
	if (p_req.has("bind") && p_req["bind"].get_type() == Variant::STRING) {
		bind = p_req["bind"];
	}
	if (bind.is_empty()) {
		snap_state().last_err = "nobind";
		return String("{\"ok\":0,\"err\":\"nobind\"}");
	}
	// 测试入侵位：原版拒签并回报 b（脚本 账本快照.gd 的 测试入侵位 会带 test_block）
	int64_t test_block = 0;
	if (p_req.has("test_block")) {
		test_block = snap_int_of(p_req["test_block"]);
	}
	if (test_block != 0) {
		snap_state().refused++;
		snap_state().last_err = "blocked";
		return String("{\"ok\":0,\"err\":\"blocked\",\"b\":") + itos(test_block) + String("}");
	}
	String payload;
	if (p_req.has("payload") && p_req["payload"].get_type() == Variant::STRING) {
		payload = p_req["payload"];
	}
	if (payload.is_empty()) {
		Dictionary data = snap_current_save_data();
		if (data.is_empty()) {
			// 不在保存流程内（或 LocalSaveManager 未就绪）：不伪造空快照，
			// 空 payload 会让官方比对出全量 diff 从而封印账本。
			snap_state().last_err = "nosnap";
			return String("{\"ok\":0,\"err\":\"nosnap\"}");
		}
		payload = snap_payload_of(snap_live_counts(data));
	}
	String seal = snap_build_seal(bind, payload);
	snap_state().sealed++;
	snap_state().last_err = String();
	return String("{\"ok\":1,\"n\":") + itos(snap_payload_sections(payload)) +
			",\"seal\":\"" + seal.json_escape() + "\"}";
}

String rpc_string(const Dictionary &p_d, const char *p_key) {
	if (!p_d.has(p_key)) {
		return String();
	}
	Variant v = p_d[p_key];
	if (v.get_type() != Variant::STRING) {
		return String();
	}
	return v;
}

} // namespace

// 0x3413190
int XiewaCore::core_version() {
	return 7;
}

// 0x391A180：算 SHA-256("") 与常量逐字节比，相等 1 否则 0
int XiewaCore::core_selftest() {
	uint8_t d[32];
	util::sha256("", 0, d);
	String hex = util::to_hex32(d);
	return util::ct_equal(hex, String(kSha256Empty)) ? 1 : 0;
}

// 0x34131B0：String → SHA-256 → 小写 hex 写回
String XiewaCore::core_sha256_hex(const String &data) {
	uint8_t d[32];
	CharString u8 = data.utf8();
	util::sha256(u8.get_data(), (size_t)u8.length(), d);
	return util::to_hex32(d);
}

// 0x3413300：6 字符字面量（RVA 0x4EA3615），语义未明，原样返回
String XiewaCore::core_shell() {
	return String(".fDept");
}

// 0x3413340：信封分发
String XiewaCore::core_rpc(const String &envelope) {
	Variant parsed = JSON::parse_string(envelope);
	if (parsed.get_type() != Variant::DICTIONARY) {
		return String(kRpcParseFail);
	}
	Dictionary d = parsed;

	String fn = rpc_string(d, "fn");
	if (fn.is_empty()) {
		return String(kRpcFnFail);
	}

	// ---- 第三路：snap_* ----
	if (fn.begins_with("snap_")) {
		if (fn == String("snap_status")) {
			// 0x39290BD
			return snap_status_json();
		}
		if (fn == String("snap_open")) {
			// 0x3928C89
			return snap_open(d);
		}
		if (fn == String("snap_rebind")) {
			// 0x392901E
			return snap_rebind(d);
		}
		if (fn == String("snap_seal")) {
			// 0x3928FA4
			return snap_seal(d);
		}
		return String(kRpcFnFail);
	}

	// ---- ledger_*：经济账本接口 ----
	// 脚本 经济账本.gd:可用() 要求 ledger_stats 回 ok=1，否则 LEDGER 不可用，
	// 而 账本快照.gd:可用() 又要求 LEDGER 可用 —— 缺这一路会导致快照整体停用、
	// header 永不写 ledger_snap，读档被 读档核对() 判成 missing。
	// 这里按观察模式实现：不回 diff、不回 flags，避免误判与误封。
	if (fn.begins_with("ledger_")) {
		if (fn == String("ledger_stats")) {
			return String("{\"ok\":1}");
		}
		if (fn == String("ledger_reset") || fn == String("ledger_load")) {
			return String(kRpcOk);
		}
		if (fn == String("ledger_check")) {
			// 不能回 n>0：脚本会把每一行写进 记事件，并且 对齐段() 会据此判不符
			return String("{\"ok\":1,\"n\":0}");
		}
		if (fn == String("ledger_apply") || fn == String("ledger_ev_end") || fn == String("ledger_flow")) {
			// flags 必须为空数组：非空会被 记事件("账本标记"/"账本语义不符")
			return String("{\"ok\":1,\"flags\":[]}");
		}
		if (fn == String("ledger_ev_begin")) {
			// e 回空串，_交原生() 会因 e 为空直接返回 []，不产生后续语义校验
			return String("{\"ok\":1,\"e\":\"\"}");
		}
		if (fn == String("ledger_pity")) {
			// r 非 0 即视为校验通过（脚本只在 r==0 时报保底不符）
			return String("{\"ok\":1,\"r\":1}");
		}
		if (fn == String("ledger_drop_issue")) {
			return String("{\"ok\":1,\"t\":\"\"}");
		}
		if (fn == String("ledger_drop_claim")) {
			return String("{\"ok\":1,\"r\":-1}");
		}
		return String(kRpcFnFail);
	}

	// ---- 第一路：rng_test_seed（13 字符）+ qa 校验 ----
	if (fn == String("rng_test_seed")) {
		Variant qa = d.has("qa") ? d["qa"] : Variant();
		bool is_qa = false;
		if (qa.get_type() == Variant::BOOL) {
			is_qa = (bool)qa;
		} else if (qa.get_type() == Variant::INT) {
			is_qa = (int64_t)qa != 0;
		} else if (qa.get_type() == Variant::STRING) {
			String sv = qa;
			is_qa = !sv.is_empty() && sv != String("0");
		}
		if (!is_qa) {
			return String(kRpcNotQa);
		}
		return String(kRpcOk);
	}

	// ---- 第二路：rules_load_signed（17 字符）body + sig ----
	if (fn == String("rules_load_signed")) {
		String body = rpc_string(d, "body");
		String sig = rpc_string(d, "sig");
		if (body.is_empty() || sig.is_empty()) {
			return String(kRpcSigFail);
		}
		Ref<XiewaGuard> guard;
		guard.instantiate();
		if (guard.is_null()) {
			return String(kRpcSigFail);
		}
		uint8_t mac[32];
		PackedByteArray pep = guard->pepper();
		if (pep.size() == 0) {
			return String(kRpcSigFail);
		}
		CharString msg = body.utf8();
		util::hmac_sha256(pep.ptr(), (size_t)pep.size(), msg.get_data(), (size_t)msg.length(), mac);
		String expect = util::to_hex32(mac).substr(0, 17);
		if (!util::ct_equal(sig, expect)) {
			return String(kRpcSigFail);
		}
		return String(kRpcOk);
	}

	return String(kRpcFnFail);
}

// 0x3927060：HMAC-SHA256 自检（RFC 4231 Test Case 2）
int XiewaCore::core_rules_selftest() {
	uint8_t mac[32];
	util::hmac_sha256(String("Jefe"), String("what do ya want for nothing?"), mac);
	String hex = util::to_hex32(mac);
	return util::ct_equal(hex, String(kHmacTc2)) ? 1 : 0;
}

} // namespace xiewa
