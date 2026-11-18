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

// snap_open：校验 seal 的 hex 与 (bind, payload) 的重算值
String snap_open(const Dictionary &p_req) {
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
		snap_state().open_bad++;
		snap_state().last_err = "parse";
		return String(kRpcBad);
	}
	if (!util::ct_equal(snap_msg_hex(bind, payload), hex)) {
		snap_state().open_bad++;
		snap_state().last_err = "bad";
		return String(kRpcBad);
	}
	snap_state().opened++;
	return String(kRpcOk);
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

// snap_seal：需要一个 payload 才能封存；原版由 0x392C270 从引擎内部经济段自行生成，
// 这里没有等价数据源，因此只在入参显式带来 payload 时封存，否则如实返回拒绝。
String snap_seal(const Dictionary &p_req) {
	String bind;
	String payload;
	if (p_req.has("bind")) {
		Variant v = p_req["bind"];
		if (v.get_type() == Variant::STRING) {
			bind = v;
		}
	}
	if (p_req.has("payload")) {
		Variant v = p_req["payload"];
		if (v.get_type() == Variant::STRING) {
			payload = v;
		}
	}
	if (payload.is_empty()) {
		snap_state().last_err = "nosnap";
		return String("{\"ok\":0,\"err\":\"nosnap\"}");
	}
	String seal = snap_build_seal(bind, payload);
	snap_state().sealed++;
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
