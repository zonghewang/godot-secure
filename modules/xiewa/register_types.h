#pragma once

// 与模块名绑定：modules/register_module_types.gen.cpp 会按 config.py 自动生成
// initialize_xiewa_module / uninitialize_xiewa_module 的调用，因此函数名必须叫这个。
#include "modules/register_module_types.h"

void initialize_xiewa_module(ModuleInitializationLevel p_level);
void uninitialize_xiewa_module(ModuleInitializationLevel p_level);
