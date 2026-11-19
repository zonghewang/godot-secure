// =============================================================================
//  xiewa_core_bind.cpp —— 把 XiewaCore 的 6 个静态方法暴露给脚本
//
//  全部是 bind_static_method：GDScript 侧用
//      ClassDB.class_call_static("XiewaCore", "core_version")
//  这种形式调用（见 globals/账本快照.gd、经济账本.gd 的 _rpc）。
//  XiewaCore 是抽象类，脚本不能 new，所以只绑静态方法。
// =============================================================================

#include "xiewa_core.h"

#include "core/object/class_db.h"

using namespace xiewa;

void XiewaCore::_bind_methods() {
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_version"), &XiewaCore::core_version);
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_selftest"), &XiewaCore::core_selftest);
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_sha256_hex", "data"), &XiewaCore::core_sha256_hex);
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_shell"), &XiewaCore::core_shell);
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_rpc", "envelope"), &XiewaCore::core_rpc);
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_rules_selftest"), &XiewaCore::core_rules_selftest);
}
