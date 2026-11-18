// =============================================================================
//  xiewa_guard_bind.cpp —— XiewaGuard::_bind_methods() 的 54 条真实绑定
//
//  用法：把本文件的函数体替换进 xiewa_guard.cpp 里的 XiewaGuard::_bind_methods()，
//        或直接把本文件当独立编译单元（SCsub 已 add_source_files "*.cpp"，会自动编）。
//
//  对应关系（原程序）：
//    0x340C600  = XiewaGuard::_bind_methods   → 组A 21 条 + 尾部调 0x38F2A50 / 0x3910350
//    0x38F2A50  = 组B 12 条（在同一 _bind_methods 尾部被 call）
//    0x3910350  = 组C 21 条（同上）
//    0xCCE1A0   = bind_methodfi 本体（bind_method / bind_static_method 共用），三批共用
//  因此 54 条全部属于 XiewaGuard 一个类，一次性绑完即可。
//
//  ★ 2026-11-16：这 54 条改为 bind_static_method（静态绑定）。
//    原因：脚本侧是「XiewaGuard.方法()」的静态调用，实例绑定会触发
//    "Method is not static."（core/core_bind.cpp:1724 ClassDB::class_call_static）。
//    这些实现的 C++ 侧只碰文件级全局量，改成 static 成员函数不改变行为。
//
//  ★ 方法名必须逐字符等于 .rdata 里的绑定串（下面每条注释都标了源串地址），
//    否则 pck 里脚本的 has_method("…") 会静默失配。
//  ★ 参数名只是编辑器/文档展示用，不影响调用；这里按语义起名。
//  ★ 返回类型由 C++ 签名自动登记，不需要额外声明。
// =============================================================================

#include "xiewa_guard.h"

#include "core/object/class_db.h"

using namespace xiewa;

void XiewaGuard::_bind_methods() {
	// ---------------------------------------------------------------- 组A 21 条
	// 批函数 0x340C600；名称簇 0x50A2E80–0x50A2EAF
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("configure_runtime_detection", "cfg"), &XiewaGuard::configure_runtime_detection); // 名 0x50A2E80  绑定 0x340C721  实现 0x38EA8E0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("scan_runtime_detection", "opts"), &XiewaGuard::scan_runtime_detection);                 // 名 0x50A2E9C  绑定 0x340C841  实现 0x38ECA00
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("audio_output_identity"), &XiewaGuard::audio_output_identity);                   // 名 0x50A2EB3  绑定 0x340C888  实现 0x38F04F0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("device_wrap", "in"), &XiewaGuard::device_wrap);                                 // 名 0x50A2EC9  绑定 0x340C8CF  实现 0x340D7E0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("device_unwrap", "in"), &XiewaGuard::device_unwrap);                             // 名 0x50A2ED5  绑定 0x340C916  实现 0x340DA40
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("device_wrap_m", "in"), &XiewaGuard::device_wrap_m);                             // 绑定 0x340C95D  实现 0x340DCB0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("device_unwrap_m", "in"), &XiewaGuard::device_unwrap_m);                         // 绑定 0x340C9A4  实现 0x340DED0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("device_tag", "seed"), &XiewaGuard::device_tag);                                         // 绑定 0x340CAC1  实现 0x340E0F0（1938 B）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("pepper"), &XiewaGuard::pepper);                                                 // 绑定 0x340CBE1  实现 0x340E890（461 B）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("reg_write", "vendor", "subkey", "name", "data"), &XiewaGuard::reg_write);                          // 绑定 0x340CD01  实现 0x340EA60
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("reg_read", "vendor", "subkey", "name"), &XiewaGuard::reg_read);                                     // 绑定 0x340CE21  实现 0x340ECE0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("reg_erase", "vendor", "subkey", "name"), &XiewaGuard::reg_erase);                        // 绑定 0x340CF41  实现 0x340F0F0（HKCU + KEY_SET_VALUE + RegDeleteValueW）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("flush_file", "path"), &XiewaGuard::flush_file);                                 // 绑定 0x340D061  实现 0x340F320
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("move_file_durable", "from", "to"), &XiewaGuard::move_file_durable);             // 绑定 0x340D0A8  实现 0x340F400
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("single_instance_acquire", "name"), &XiewaGuard::single_instance_acquire);               // 绑定 0x340D0EF  实现 0x340F520
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("is_release_template"), &XiewaGuard::is_release_template);                       // 绑定 0x340D211  实现 0x340F590（mov al,1;ret）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("flavor"), &XiewaGuard::flavor);                                                 // 绑定 0x340D258  实现 0x340F5A0（"release"）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("vendor"), &XiewaGuard::vendor);                                                 // 绑定 0x340D29F  实现 0x340F5E0（"Ombrel"）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("reg_subkey"), &XiewaGuard::reg_subkey);                                         // 绑定 0x340D2E6  实现 0x340F620（"Cache"）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("cache_dir"), &XiewaGuard::cache_dir);                                           // 绑定 0x340D32D  实现 0x340F660（"cache"）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("mutex_name"), &XiewaGuard::mutex_name);                                         // 绑定 0x340D374  实现 0x340F6A0（固定 GUID 串）

	// ---------------------------------------------------------------- 组B 12 条
	// 批函数 0x38F2A50；名称簇 0x51F6579–0x51F65FF
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("device_wrap2", "in"), &XiewaGuard::device_wrap2);                               // 名 0x51F6579  绑定 0x38F2A96  实现 0x38F1970
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("device_unwrap2", "in"), &XiewaGuard::device_unwrap2);                           // 名 0x51F6586  绑定 0x38F2ADD  实现 0x38F1B40
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("device_wrap_m2", "in"), &XiewaGuard::device_wrap_m2);                           // 名 0x51F6595  绑定 0x38F2B24  实现 0x38F1C70
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("device_unwrap_m2", "in"), &XiewaGuard::device_unwrap_m2);                       // 名 0x51F65A4  绑定 0x38F2B6B  实现 0x38F2000
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("sign2", "label", "key", "body"), &XiewaGuard::sign2);                                             // 名 0x51F65B5  绑定 0x38F2BB2  实现 0x38F2050
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("derive2", "label", "seed", "rounds"), &XiewaGuard::derive2);                                         // 名 0x51F65BB  绑定 0x38F2BF9  实现 0x38F2510
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("verify2", "label", "key", "body", "mac"), &XiewaGuard::verify2);                                         // 名 0x51F65C3  绑定 0x38F2C40  实现 0x38F2300
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("sign_blocked"), &XiewaGuard::sign_blocked);                                     // 名 0x51F65CB  绑定 0x38F2C87  实现 0x38F2460
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("test_block", "in"), &XiewaGuard::test_block);                                   // 名 0x51F65D8  绑定 0x38F2CCE  实现 0x38F8790
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("editor_check", "what", "opts"), &XiewaGuard::editor_check);                               // 名 0x51F65E3  绑定 0x38F2D15  实现 0x38F2DB0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("editor_cleanup", "in"), &XiewaGuard::editor_cleanup);                           // 名 0x51F65F0  绑定 0x38F2D5C  实现 0x38F3250
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("name2", "in", "suffix"), &XiewaGuard::name2);                                             // 名 0x51F65FF  绑定 0x38F2DA3  实现 0x38F36F0

	// ---------------------------------------------------------------- 组C 21 条
	// 批函数 0x3910350；串区 0x52A23EA 附近
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("bridge_check", "flags"), &XiewaGuard::bridge_check);                            // 绑定 0x3910471  实现 0x38F7AD0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("script_integrity", "opts"), &XiewaGuard::script_integrity);                     // 绑定 0x3910591  实现 0x3E13260
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("engine_flags"), &XiewaGuard::engine_flags);                                     // 绑定 0x39105D8  实现 0x38F8820
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("machine_fp"), &XiewaGuard::machine_fp);                                         // 绑定 0x391061F  实现 0x38F7230
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("devlimit_state"), &XiewaGuard::devlimit_state);                                 // 绑定 0x3910655  实现 0x38F7230（同体）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("devlimit_mark", "v"), &XiewaGuard::devlimit_mark);                              // 绑定 0x391069C  实现 0x38FBE00
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("devlimit_clear", "token", "scope"), &XiewaGuard::devlimit_clear);                            // 绑定 0x39107C1  实现 0x390E670
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("defer_note", "v"), &XiewaGuard::defer_note);                                    // 绑定 0x3910808  实现 0x38FC640
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("defer_boot"), &XiewaGuard::defer_boot);                                          // 绑定 0x3910921  实现 0x38FF4C0；原始 argc=0/defcnt=0（无入参、无默认值）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("defer_state"), &XiewaGuard::defer_state);                                       // 绑定 0x3910957  实现 0x38FF4C0（同体）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("list_apply", "v"), &XiewaGuard::list_apply);                                    // 绑定 0x3910A71  实现 0x3906250
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("list_state"), &XiewaGuard::list_state);                                         // 绑定 0x3910AA7  实现 0x3906250（同体）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("list_raw"), &XiewaGuard::list_raw);                                             // 绑定 0x3910BC1  实现 0x390C7E0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("list_check_profile", "profile"), &XiewaGuard::list_check_profile);               // 绑定 0x3910CE1  实现 0x390C860
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("id_hash", "id"), &XiewaGuard::id_hash);                                         // 绑定 0x3910D28  实现 0x390CB50
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("list_check_hash", "hash", "kind"), &XiewaGuard::list_check_hash);                       // 绑定 0x3910E41  实现 0x390CA20
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("svc_verify", "sig"), &XiewaGuard::svc_verify);                                  // 绑定 0x3910E77  实现 0x390CA20（同体）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("ck_state", "key"), &XiewaGuard::ck_state);                                             // 绑定 0x3910F25  实现 0x390CA20（同体）
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("unseal_receipt", "key", "machine", "salt", "channel", "extra"), &XiewaGuard::unseal_receipt);                          // 绑定 0x3911051  实现 0x390F1A0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("receipt_ok", "receipt", "expect", "seg", "salt", "channel"), &XiewaGuard::receipt_ok);                     // 绑定 0x3911171  实现 0x390FFA0
	ClassDB::bind_static_method("XiewaGuard", D_METHOD("unseal_legacy_ok", "receipt"), &XiewaGuard::unseal_legacy_ok);                   // 绑定 0x39111B8  实现 0x3910070
}
