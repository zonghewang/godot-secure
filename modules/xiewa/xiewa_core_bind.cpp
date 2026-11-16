// =============================================================================
//  xiewa_core_bind.cpp —— XiewaCore::_bind_methods() 的 6 条真实绑定
//
//  对应关系（原程序）：
//    XiewaCore 在 0x17ED380 注册（register_abstract_class，class_db.h:0x113），
//    紧接着 0x17ED416 调 0x3412670 = XiewaCore::_bind_methods（MethodInfo 0x50 字节）。
//    方法名簇起点 0x50A35B8：XiewaCore / core_version / core_selftest /
//    core_sha256_hex / core_shell / core_rpc / core_rules_selftest
//
//  注意：抽象类只声明不实现，脚本侧不能 new，只能被 C++ 或内部调用；
//        GDREGISTER_ABSTRACT_CLASS 已在 register_types.cpp 里注册。
// =============================================================================

#include "xiewa_core.h"

#include "core/object/class_db.h"

using namespace xiewa;

void XiewaCore::_bind_methods() {
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_version"), &XiewaCore::core_version);                                   // 绑定点在 0x3412670 批内，名簇 0x50A35B8 起
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_selftest"), &XiewaCore::core_selftest);
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_sha256_hex", "data"), &XiewaCore::core_sha256_hex);
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_shell"), &XiewaCore::core_shell);
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_rpc", "envelope"), &XiewaCore::core_rpc);
	ClassDB::bind_static_method("XiewaCore", D_METHOD("core_rules_selftest"), &XiewaCore::core_rules_selftest);
}
