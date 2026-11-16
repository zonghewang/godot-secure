// =============================================================================
//  register_types.cpp —— 模块注册入口（这就是"启动类"要挂的地方）
//
//  调用链（Godot 4.x）：
//    main/main.cpp  Main::setup()
//      └─ register_module_types()                 // 位于 modules/register_module_types.gen.cpp
//           └─ initialize_xiewa_module(SCENE)     // ← 本文件，构建系统自动生成调用，无需手改
//                └─ GDREGISTER_CLASS(XiewaGuard)  // 对应 exe 里 0x17ED770 的 register_class
//                └─ GDREGISTER_ABSTRACT_CLASS(XiewaCore)  // 对应 0x17ED380
//
//  对应原程序：XiewaGuard 在 0x17ED770、XiewaCore 在 0x17ED380 各自做一次
//  "守卫字节判重 → ClassDB::register_class → _bind_methods"。
//  GDREGISTER_CLASS 宏内部就是 register_class + _bind_methods，语义完全一致。
//
//  注册级别为什么选 SCENE：
//    XiewaGuard 父类是 RefCounted/Object，只有到 SCENE 级 ClassDB/Object 体系才完备。
//    （MODULE_INITIALIZATION_LEVEL_CORE 只有最底层的 core 类型可用。）
// =============================================================================

#include "register_types.h"

#include "core/object/class_db.h"

#include "xiewa_guard.h"
#include "xiewa_core.h"

// 两个类的实现都放在 namespace xiewa 里（与原程序命名空间一致），
// GDREGISTER_* 宏要求写出完整类型名，这里用 using 声明统一限定。
using namespace xiewa;

void initialize_xiewa_module(ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
		return;
	}

	// 具体类 → 对应 0x17ED770（register_class，54 个方法）
	GDREGISTER_CLASS(XiewaGuard);

	// 抽象类 → 对应 0x17ED380（register_abstract_class，6 个 core_* 方法）
	GDREGISTER_ABSTRACT_CLASS(XiewaCore);

	// 注意：xiewa_guard2d 命名空间里的 CurrentProcessReader / ImageReader
	// 是内部实现类，原程序**没有**注册进 ClassDB（无 register_class 调用），
	// 所以这里也不注册，只作为 .cpp 编进模块随 XiewaGuard 一起用。
}

void uninitialize_xiewa_module(ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
		return;
	}
	// 原程序无注销逻辑（进程生命周期内一直有效），此处保持空实现。
}
