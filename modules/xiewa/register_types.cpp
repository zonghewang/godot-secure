// =============================================================================
//  register_types.cpp —— 模块注册入口
//
//  Godot 启动时由自动生成的 register_module_types 调用本文件的
//  initialize_xiewa_module()，在这里把两个类登记进 ClassDB：
//    · XiewaGuard —— 具体类，脚本可以直接 new（守护/校验的主力）
//    · XiewaCore  —— 抽象类，只提供 6 个静态 core_* 方法
//
//  用 SCENE 级别：XiewaGuard 继承 RefCounted，要到 SCENE 这一级
//  ClassDB/Object 体系才完整（CORE 级只有最底层类型可用）。
// =============================================================================

#include "register_types.h"

#include "core/object/class_db.h"

#include "xiewa_guard.h"
#include "xiewa_core.h"

// 两个类都定义在 namespace xiewa 里
using namespace xiewa;

void initialize_xiewa_module(ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
		return;
	}

	GDREGISTER_CLASS(XiewaGuard);
	GDREGISTER_ABSTRACT_CLASS(XiewaCore);

	// xiewa_guard2d 里的 CurrentProcessReader / ImageReader 是内部实现类，
	// 原程序也没注册进 ClassDB，所以这里不注册，只随模块一起编译。
}

void uninitialize_xiewa_module(ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) {
		return;
	}
	// 原程序没有注销逻辑（进程内一直有效），保持空实现。
}
