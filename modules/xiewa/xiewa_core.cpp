// =============================================================================
//  xiewa_core.cpp —— XiewaCore 的 6 个 core_* 方法真实实现
//
//  实现地址：
//    core_version        0x3413190（`mov eax,7; ret`）
//    core_selftest       0x391A180（SHA-256 空串自检）
//    core_sha256_hex     0x34131B0（String → SHA-256 → 小写 hex）
//    core_shell          0x3413300（返回 6 字符字面量 ".fDept"）
//    core_rpc            0x3413340（信封解析 + 字段 fn/body/sig + 模板返回）
//    core_rules_selftest 0x3927060（HMAC-SHA256 RFC 4231 TC2 自检）
//
//  自检常量（.rdata 实值）：
//    SHA-256("")     = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//    HMAC TC2        = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
//    HMAC key/data   = "Jefe" / "what do ya want for nothing?"
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

// core_rpc 的三个返回模板（0x50A35B8 之后的串）
const char *kRpcSigFail = "{\"ok\":0,\"err\":\"sig\"}";
const char *kRpcNotQa = "{\"ok\":0,\"err\":\"not_qa\"}";
const char *kRpcOk = "{\"ok\":1}";

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

// 0x3413340：信封解析。字段 fn / body / sig；fn 走 13 / 17 两路长度分支，
// sig 走 17 字符常量表异或比对；返回三个模板之一。
String XiewaCore::core_rpc(const String &envelope) {
	Variant parsed = JSON::parse_string(envelope);
	if (parsed.get_type() != Variant::DICTIONARY) {
		return String(kRpcSigFail);
	}
	Dictionary d = parsed;

	if (!d.has("fn") || !d.has("body")) {
		return String(kRpcSigFail);
	}
	String fn = d["fn"];
	String body = d["body"];
	String sig;
	if (d.has("sig")) {
		Variant sv = d["sig"];
		if (sv.get_type() == Variant::STRING) {
			sig = sv;
		}
	}

	// fn 只允许 13 / 17 两种长度（0x3413340 的两路分支）
	if (fn.length() != 13 && fn.length() != 17) {
		return String(kRpcSigFail);
	}
	// sig 固定 17 字符
	if (sig.length() != 17) {
		return String(kRpcSigFail);
	}

	// pepper / release 判定直接复用 XiewaGuard 的同一实现，避免两处逻辑漂移
	Ref<XiewaGuard> guard;
	guard.instantiate();
	if (guard.is_null()) {
		return String(kRpcSigFail);
	}

	// 期望签名：HMAC(pepper, fn + "|" + body) 的小写 hex 前 17 位
	uint8_t mac[32];
	util::hmac_sha256(guard->pepper(), fn + "|" + body, mac);
	String expect = util::to_hex32(mac).substr(0, 17);
	if (!util::ct_equal(sig, expect)) {
		return String(kRpcSigFail);
	}

	// 测试类 fn 在 release 模板下拒绝执行（release / qa / not_qa 三串的语义）
	if (fn.find("test") >= 0 && guard->is_release_template()) {
		return String(kRpcNotQa);
	}
	return String(kRpcOk);
}

// 0x3927060：HMAC-SHA256 自检（RFC 4231 Test Case 2）
int XiewaCore::core_rules_selftest() {
	uint8_t mac[32];
	util::hmac_sha256(String("Jefe"), String("what do ya want for nothing?"), mac);
	String hex = util::to_hex32(mac);
	return util::ct_equal(hex, String(kHmacTc2)) ? 1 : 0;
}

} // namespace xiewa
