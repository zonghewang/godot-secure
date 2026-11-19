// =============================================================================
//  xiewa_core.h —— XiewaCore：脚本层调用的 6 个静态工具函数
//
//  这个类只做四件事：报版本号、跑两个自检、算 SHA-256、分发 core_rpc 信封。
//  用 register_abstract_class 注册，脚本侧不能 new，只能 ClassDB.class_call_static。
//  6 个方法都有实体实现（不是纯虚），对应原程序 0x3413190 等地址。
// =============================================================================

#pragma once

#include "core/object/object.h"
#include "core/variant/variant.h"

namespace xiewa {

class XiewaCore : public Object {
	GDCLASS(XiewaCore, Object);

protected:
	static void _bind_methods();

public:
	// 版本号，固定 7（脚本用它判断引擎这一侧有没有账本/快照能力）
	static int core_version();

	// SHA-256 空串自检：算得与标准值一致返回 1，否则 0
	static int core_selftest();

	// String → SHA-256 → 小写 hex
	static String core_sha256_hex(const String &data);

	// 原程序返回固定字面量 ".fDept"，语义未明，这里原样保留
	static String core_shell();

	// JSON 信封分发：按 fn 走 rng_test_seed / rules_load_signed / snap_* / ledger_*
	static String core_rpc(const String &envelope);

	// HMAC-SHA256 自检（RFC 4231 Test Case 2）：正确返回 1
	static int core_rules_selftest();
};

}  // namespace xiewa
