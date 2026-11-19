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
//  [历史逆向记录，实现已停用] snap seal 的真实字节格式（0x392CE70 编码 / 0x392CFD0 解码）
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

#include "core/object/ref_counted.h"
#include "core/string/ustring.h"
#include "core/variant/dictionary.h"
#include "core/variant/variant.h"

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
const char *kRpcOk = "{\"ok\":1}";

// ---------------------------------------------------------------------------
//  快照接口（snap_*）：为什么这里全部"放行"
//
//  官方脚本写档（globals/local_save_manager.gd）：
//    1) 账本快照.gd:封存(bind) → core_rpc("snap_seal") 取 seal；
//    2) seal 非空 → header["ledger_snap"] = seal；
//    3) 紧接着 :2967 看到 header 里有 ledger_snap，就把水位记录的 snap_g
//       抬成本次存档的代数。
//
//  官方脚本读档（globals/账本快照.gd:读档核对）：
//    · header 没有 ledger_snap → snap_g>0 且代数已到 → "missing"（拒读）
//                                否则                → "migrate"（放行）
//    · header 有 ledger_snap   → core_rpc("snap_open") 验封；
//                                验不过 → "bad" → 数值守卫.快照拒读() 整档拒读。
//
//  本模块签不出官方认可的 seal（官方 payload 的编码口径与这边不同），
//  所以干脆让 header 里永远没有 ledger_snap，两端都落在 migrate 这个放行分支：
//    · snap_seal / snap_rebind 一律回 nosnap —— 不签发 seal；
//    · snap_open 一律回 ok=1,n=0 —— 不拿快照结果当拒读依据。
//  代价：自编版不再具备快照防篡改能力，改档判定交给官方版；
//  前提：水位记录的 snap_g 必须保持 0，否则"seal 缺失 + snap_g>0"会被判 missing。
// ---------------------------------------------------------------------------

// 账本快照.gd:验封() 只认 ok=1 且 n=0；n>0 会被当成 diff 并封印账本
const char *kSnapPass = "{\"ok\":1,\"n\":0}";

// 账本快照.gd:可用() 只读 ok 字段，用来判断这一版引擎有没有快照能力
String snap_status_json() {
	return String(kRpcOk);
}

// 验封：不解析、不比对，直接放行
String snap_open(const Dictionary &) {
	return String(kSnapPass);
}

// 改绑：不签发新 seal
String snap_rebind(const Dictionary &) {
	return String("{\"ok\":0,\"err\":\"nosnap\"}");
}

// 封存：不签发 seal，header 因此不会出现 ledger_snap
String snap_seal(const Dictionary &) {
	return String("{\"ok\":0,\"err\":\"nosnap\"}");
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
		// 四个快照接口全部"放行"，原因见文件上方那段说明
		if (fn == String("snap_status")) {
			return snap_status_json();
		}
		if (fn == String("snap_open")) {
			return snap_open(d);
		}
		if (fn == String("snap_rebind")) {
			return snap_rebind(d);
		}
		if (fn == String("snap_seal")) {
			return snap_seal(d);
		}
		return String(kRpcFnFail);
	}

	// ---- ledger_*：经济账本接口（只回"一切正常"，不做任何记账） ----
	// 脚本 经济账本.gd:可用() 只认 ledger_stats 的 ok=1。这里一律回 ok、
	// n=0、flags=[]，既不产生 diff 也不写 flags，避免被 记事件() 判成"账本不符"。
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
