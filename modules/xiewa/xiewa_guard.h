// =============================================================================
//  XiewaGuard.h  —— 由静态逆向还原的类定义（声明级，非原创源码）
//  ★ 本版已扩到全部 54 个方法（组A 21 + 组B 12 + 组C 21）
//
//  来源      : E:\gamezip\XiewaPai\XiewaPai.exe
//  大小/哈希 : 90,098,688 B / 9AF23B57A21ACDF30EBE09DEE97B7E03C2A759F3B1D5B318BFFCA4F8926B6081
//  引擎      : Godot 4.x（纯原生，无 .NET）
//  还原方式  : capstone 反汇编 + ClassDB 绑定序列解析 + IAT 导入名解析
//  还原程度  : 类名 / 父类 / 全部方法名 / 每个方法的绑定点与实现 RVA / 实际调用的系统 API；
//              方法体内部完整控制流、结构体成员名未逐字节还原（本机无反编译器）。
//  标注      : [确认] 反汇编直接可见   [推定] 由调用约定与上下文推断
//
//  绑定拓扑（关键）：
//      0x17ED770  cmp byte[0x563F38C],0 → call 0xCBE880(register_class) →
//                 call 0x340C600 (_bind_methods) → mov byte[0x563F38C],1
//      0x340C600  逐条 lea r9,"方法名" + call 0xCCE1A0  …… 共 21 条（组A）
//                 → 0x340D379 call 0x38F2A50  …… 组B 12 条
//                 → 0x340D37E call 0x3910350  …… 组C 21 条
//  即：组A/组B/组C 同属 XiewaGuard 一个类（三批 MethodInfo 均 0x58 字节）。
// =============================================================================

#pragma once

#include "core/object/ref_counted.h"
#include "core/variant/variant.h"

namespace xiewa {

// ClassDB 注册名 "XiewaGuard"，父类 RefCounted，无成员变量（状态全在 .data 全局）。
// 类名串 RVA 0x4B9AD2E；类槽 0x563F390；父类槽 0x563F200；守卫字节 0x563F38C。
class XiewaGuard : public RefCounted {
    GDCLASS(XiewaGuard, RefCounted);

protected:
    static void _bind_methods();   // 0x340C600（内部再调 0x38F2A50 / 0x3910350）

public:
    // =========================================================================
    //  组A —— 第一代守卫（21 条，绑定点 0x340C721 … 0x340D374）
    // =========================================================================

    // ---------------------------------------------------------------------
    //  ⚠ 2026-11-15 修正：组A 的「方法→实现」映射此前整体错位一位
    //     （旧做法取 bind 点之后的 lea；实测两种绑定块形态都是 lea 在 bind 之前）。
    //     21 条已按 `0x340C600–0x340D390` 逐块重算，见下表；旧产物中依赖旧映射
    //     得出的语义（尤其 device_tag 与 pepper「同体」、reg_erase 名实不符）已标注待复核。
    //     configure_runtime_detection 0x340C721 → 0x38EA8E0（4184 B，配置解析）
    //     scan_runtime_detection     0x340C841 → 0x38ECA00（镜像校验驱动）
    //     audio_output_identity      0x340C888 → 0x38F04F0
    //     device_wrap                0x340C8CF → 0x340D7E0
    //     device_unwrap              0x340C916 → 0x340DA40
    //     device_wrap_m              0x340C95D → 0x340DCB0
    //     device_unwrap_m            0x340C9A4 → 0x340DED0
    //     device_tag                 0x340CAC1 → 0x340E0F0
    //     pepper                     0x340CBE1 → 0x340E890
    //     reg_write                  0x340CD01 → 0x340EA60
    //     reg_read                   0x340CE21 → 0x340ECE0
    //     reg_erase                  0x340CF41 → 0x340F0F0
    //     flush_file                 0x340D061 → 0x340F320
    //     move_file_durable          0x340D0A8 → 0x340F400
    //     single_instance_acquire    0x340D0EF → 0x340F520
    //     is_release_template        0x340D211 → 0x340F590
    //     flavor                     0x340D258 → 0x340F5A0
    //     vendor                     0x340D29F → 0x340F5E0
    //     reg_subkey                 0x340D2E6 → 0x340F620
    //     cache_dir                  0x340D32D → 0x340F660
    //     mutex_name                 0x340D374 → 0x340F6A0
    // ---------------------------------------------------------------------

    // 一、运行时检测
    // 绑定 @0x340C721，实现 0x38EA8E0 [确认]
    // [确认] 接收配置字典：schema / scan_budget_ms[100,5000] / max_handles[1,0x10000]
    //        / max_processes[1,0x1000] / max_modules[1,0x400] / max_candidates[1,0x20]
    //        / d4_chunk_bytes[8,0x10000] / integrity_baseline(27 键) / known_modules
    static void configure_runtime_detection(const Variant &cfg);

    // 绑定 @0x340C841，实现 0x38ECA00 [确认]（驱动 xiewa_guard2d::ImageReader 的镜像校验）
    // [确认] 拆串 0x3E10170 → 按 byte[rsp+0x28]&1 判 ptr/内联 → Variant 构造 0x8A06F0。
    static Variant scan_runtime_detection();

    // 二、设备标识（Windows DPAPI + 运行期熵）
    // 绑定 @0x340C888，实现 0x38F04F0 【地址已修正】
    // [待复核·旧注迁入] 拆串 0x3E10170 → 按 byte[rsp+0x28]&1 判 ptr/内联 → Variant 构造 0x8A06F0。
    static String audio_output_identity();

    // 绑定 @0x340C8CF，实现 0x340D7E0 【地址已修正】
    // [待复核·旧注迁入] CRYPT32!CryptProtectData；32 字节熵由 0x50A3100/0x50A3120 两张表现场异或生成。
    static String device_wrap(const String &in);

    // 绑定 @0x340C916，实现 0x340DA40 【地址已修正】
    // [待复核·旧注迁入] CRYPT32!CryptUnprotectData（名字与实现相反，名字是脚本侧语义名）。
    static String device_unwrap(const String &in);

    // 绑定 @0x340C95D，实现 0x340DCB0 【地址已修正】
    // [待复核·旧注迁入] mutex_name() 取熵 + CRYPT32!CryptProtectData（szDescription="ombrel"）。
    static Variant device_wrap_m(const String &in);

    // 绑定 @0x340C9A4，实现 0x340DED0 【地址已修正】
    // [待复核·旧注迁入] 熵 + Unprotect + rep stosb 清零（擦除版）。
    static Variant device_unwrap_m(const Variant &in);

    // 绑定 @0x340CAC1，实现 0x340E0F0（1938 B）【地址已修正 + 分体确认】
    // [待复核·旧注迁入] Variant 解包 → 内联 device_wrap → 0x1026850/0x1026BA0/0x1026CC0/0x1026A70 → String::assign(0x20)。
    // 与 pepper 不再是同一体：pepper 走 0x340E890，只 461 B。
    static String device_tag();

    // 绑定 @0x340CBE1，实现 0x340E890（461 B）【地址已修正 + 分体确认】
    // [待复核·旧注迁入] 无参无系统调用：异或生成器生成固定 32 字节，String::assign(0x20) 拷出。
    static String pepper();

    // 三、注册表（HKLM，REG_BINARY）
    // 绑定 @0x340CD01，实现 0x340EA60 【地址已修正】
    // [确认] "Software\" + 串a + "\" + 串b → RegCreateKeyExW(HKLM, samDesired=0x20006)
    //        → RegSetValueExW(REG_BINARY=3) → RegCloseKey → sete sil
    static bool reg_write(const String &name, const String &value);

    // 绑定 @0x340CE21，入口 0x340ECE0
    // [确认] 同路径拼装 → RegOpenKeyExW → RegQueryValueExW 两段 → String::assign
    static String reg_read(const String &name);

    // 绑定 @0x340CF41，实现 0x340F0F0（559 B）【地址已修正 + 真体已复核】
    // [确认] 拼 "Software\" + a + "\" + b（0x50A3004 / 0x50A300E），转宽字符(0x340F9F0)
    //        → RegOpenKeyExW(HKEY_CURRENT_USER=0xFFFFFFFF80000001, key, 0, KEY_SET_VALUE=2, &hk)
    //        → RegDeleteValueW(hk, b) → RegCloseKey(hk)；开键成功且删值成功才 true。
    // ⚠ 旧结论"名实不符 / 无删除 API / HKLM"是读错位址(0x340EF00)所得，全部作废。
    // ⚠ 参数应为 2 个串（旧声明只有 name），待调用侧确认。
    static bool reg_erase(const String &subkey, const String &value);

    // 绑定 @0x340D061，入口 0x340F320
    // [确认] CreateFileW(GENERIC_WRITE=0x40000000, share=7, OPEN_EXISTING=3,
    //        FILE_ATTRIBUTE_NORMAL=0x80) → FlushFileBuffers → CloseHandle → setne sil
    static bool flush_file(const String &path);

    // 绑定 @0x340D0A8，入口 0x340F400
    // [确认] MoveFileExW(from,to,flags=8=MOVEFILE_WRITE_THROUGH)，无 REPLACE_EXISTING。
    static bool move_file_durable(const String &from, const String &to);

    // 绑定 @0x340D0EF，入口 0x340F520
    // [确认] CreateMutexW(NULL, bInitialOwner=1, mutex_name())；
    //        创建失败 bl=1（放行）；GetLastError()==0xB7 → setne bl。
    static bool single_instance_acquire();

    // 绑定 @0x340D211 / 0x340D258 / 0x340D29F / 0x340D2E6 / 0x340D32D
    // 实现 0x340F590 / 0x340F5A0 / 0x340F5E0 / 0x340F620 / 0x340F660（各 55 B，0x340F590 仅 1 B）
    // [确认·真体已复核] is_release_template 是 `mov al,1; ret`（返回 bool true，不是字符串）；
    //        flavor="release" / vendor="Ombrel" / reg_subkey="Cache" / cache_dir="cache"。
    //        四串在 .rdata 里连续排布：0x50A2FA7 / 0x50A2FAF / 0x50A2FB6 / 0x50A2FBC。
    static bool is_release_template();
    static String flavor();
    static String vendor();
    static String reg_subkey();
    static String cache_dir();

    // 绑定 @0x340D374，实现 0x340F6A0（55 B）【地址已修正 + 真体已复核】
    // [确认] 只是一次 String 赋值，返回固定字面量：
    //        "Local\Ombrel.{18657BB7-EFAC-44EA-8C0D-5D6F3E7454EB}"（51 字符 @0x50A2FC2）
    // ⚠ 旧结论"SHA-256(熵+\"xiewa-machine\"+SID)"作废：那是 0x340F6E0（393 行）的行为，
    //   而 0x340F6E0 不在组A 任一绑定点上，归属未定。
    static String mutex_name();

    // =========================================================================
    //  组B —— 第二代守卫（12 条，绑定函数 0x38F2A50，绑定点 0x38F2A96…0x38F2DA3）
    //  全部共享"拦截门"：读 0x5484D98/0x5484D9C → 非 0 返回空 String；
    //  否则读 0x560AAF4，d=w&1、n=(w&0xE)?d+2:d，n!=0 则 lock or [0x5484D98],n 并返回空。
    //  独立密码栈：0x38F12E0(SHA-256 派生) / 0x38F1730(DPAPI 分发) / 0x38F1D70(机器密钥，自递归)
    //  常量：xiewa-dpapi2 / xiewa-machine2 / xw2-derive / ombrel
    // =========================================================================

    // 名串 0x51F6579，实现 0x38F1970（285 指令）
    static String device_wrap2(const String &in);
    // 名串 0x51F6586，实现 0x38F1B40（267）—— 内含第二套异或生成器（四张真表）
    static String device_unwrap2(const String &in);
    // 名串 0x51F6595，实现 0x38F1C70（284）
    static Variant device_wrap_m2(const String &in);
    // 名串 0x51F65A4，实现 0x38F2000（292）
    static Variant device_unwrap_m2(const Variant &in);
    // 名串 0x51F65B5，实现 0x38F2050（276）—— 时间窗 0x7D0 + 副本扫描 + "save5…" 标签判定
    static String sign2(const String &in);
    // 名串 0x51F65BB，实现 0x38F2510（265）—— derive32
    static String derive2(const String &in);
    // 名串 0x51F65C3，实现 0x38F2300（280）—— 解析 + base64 + SHA-256 + 比对（非 RSA）
    static Variant verify2(const Variant &in);
    // 名串 0x51F65CB，实现 0x38F2460（270）—— 三块：双标志 / 状态门 / 时间窗+扫描（自带探测器）
    static bool sign_blocked();
    // 名串 0x51F65D8，实现 0x38F8790（238）—— evatfpall… 副本指纹测试
    static Variant test_block(const Variant &in);
    // 名串 0x51F65E3，实现 0x38F2DB0（236）
    static Variant editor_check(const Variant &in);
    // 名串 0x51F65F0，实现 0x38F3250（249）
    static Variant editor_cleanup(const Variant &in);
    // 名串 0x51F65FF，实现 0x38F36F0（270）
    static String name2(const String &in);

    // =========================================================================
    //  组C —— 桥接 / 授权 / 清单（21 条，绑定函数 0x3910350，绑定点 0x3910471…0x39111B8）
    //  与 xiewa_list.txt 的 svc.keys / bans / grace_days、XiewaPai.pck.sig 语义对应。
    //  共享件：0x39054B0（CS 内取全局）、0x38F7B60（副本扫描，参数2）、0x38FD050（状态对象）、
    //          0x38FB140（记录容器）、0x390C520（摘要内核）、0x390B240（清单校验）、
    //          0x390EA40（unseal 通道解析）、0x390F8A0（receipt 拆分）、
    //          0x39194E0（SHA-256）、0x391BD00（HMAC-SHA256）
    // =========================================================================

    // 绑定点 0x3910471，实现 0x38F7AD0（26 指令）
    // [确认] EnterCriticalSection → 0x39054B0 → LeaveCriticalSection → 0x38F7B60(2)
    //        → if (flags & 2) { ret &= 0x63; }  [推定] 返回错误掩码
    static int bridge_check(int flags);

    // 绑定点 0x3910591，实现 0x3E13260（312）
    // [确认] 走 0x24A80 / 0x3E10A00（PE 读取）；读 "bits" / "high"；按 test bl,0x7f
    //        返回 "bad" / "high" / "none" 之一（可执行完整性状态）
    static String script_integrity(const Variant &opts);

    // 绑定点 0x39105D8，实现 0x38F8820（339）
    // [确认] 组路径 "Ombrel"/"Cache" → 调 reg_read(0x340ECE0) → 0x38FA070 →
    //        LOCALAPPDATA / PROGRAMDATA 上做 JSON 读（0x6C23D0 / 0x6CDA20）
    // [推定] 返回引擎侧标记集合（"container"）
    static Variant engine_flags();

    // 绑定点 0x391061F，实现 0x38F7230（327）
    // [确认] RegGetValueW(hive=0xFFFFFFFF80000002, flags=0x10002) +
    //        GetSystemFirmwareTable('RSMB'=0x52534D42) 两段（SMBIOS 表解析，
    //        校验 byte[+1]>=4、长度 0x18、0x7f 上限、双零结尾）+ GetWindowsDirectoryW +
    //        GetVolumeInformationW
    // [推定] 返回机器指纹串
    static String machine_fp();

    // 绑定点 0x3910655，实现 0x38F7230（与 machine_fp 同体）
    static String devlimit_state();

    // 绑定点 0x391069C，实现 0x38FBE00（305）
    // [确认] 写字段 "ev" / "at" / "fp"；"at" 用 "%04d-%02d-%02dT%02d:%02d:%02d"；
    //        时间取虚调用 [rax+0x1F8]
    static Variant devlimit_mark(const Variant &v);

    // 绑定点 0x39107C1，实现 0x390E670（221）
    // [确认] 构造 "XIEWA-UNSEAL|" + … + "|M" → 0x890EA40 解析 → 清理 {Ombrel}\Cache 下记录
    static Variant devlimit_clear(const Variant &v);

    // 绑定点 0x3910808，实现 0x38FC640（316）
    // [确认] 键 "all" / "ev" / "first" / "need_d" / "need_n"
    static Variant defer_note(const Variant &v);

    // 绑定点 0x3910921，实现 0x38FF4C0（346）
    // [确认] 全局 0x548B148 首次标志；读 "first" / "need_n" / "need_d"；
    //        按 Variant 类型 switch（cmp ecx,3; ja; jmp rcx 跳表）
    static Variant defer_boot(const Variant &v);

    // 绑定点 0x3910957，实现 0x38FF4C0（与 defer_boot 同体）
    static Variant defer_state();

    // 绑定点 0x3910A71，实现 0x3906250（308）
    // [确认] 字段 "container" / "ok" / "changed" / "err" / "ver" / "sig" / "old" / "format"；
    //        Dictionary 查找走 0x7BAAB0；EnterCriticalSection
    static Variant list_apply(const Variant &v);

    // 绑定点 0x3910AA7，实现 0x3906250（与 list_apply 同体）
    static Variant list_state();

    // 绑定点 0x3910BC1，实现 0x390C7E0（135）
    // [确认] CS 包裹；全局 ready 标志 RVA 0x558A6C1（指令 0x390C810 计算得）；返回原始清单串
    static String list_raw();

    // 绑定点 0x3910CE1，实现 0x390C860（101）
    // [确认] CS → 全局标志 0x558A6C1 → 0x898ED0（取实参）/ 0x390C520 / 0x390B240
    static Variant list_check_profile(const String &profile);

    // 绑定点 0x3910D28，实现 0x390CB50（49）
    // [确认] 判 String 有效（内联/堆、"长度-1"、0x70/0x6d 类型码）→ 0x390C520
    static String id_hash(const String &id);

    // 绑定点 0x3910E41，实现 0x390CA20（79）
    // [确认] 要求 17 字符（cmp dword[arg-0x10],0x11）→ CS → 比对
    static Variant list_check_hash(const String &hash);

    // 绑定点 0x3910E77，实现 0x390CA20（与 list_check_hash 同体）
    static Variant svc_verify(const String &sig);

    // 绑定点 0x3910F25，实现 0x390CA20（同上）
    static Variant ck_state();

    // 绑定点 0x3911051，实现 0x390F1A0（331）
    // [确认] "XIEWA-UNSEAL|" + arg + "|M" → 0x890EA40 → 产出 receipt（"machine"/"receipt"/"ok"）
    static String unseal_receipt(const String &key);

    // 绑定点 0x3911171，实现 0x390FFA0（68）
    // [确认] 0x890F8A0 拆分 → 分段比较（cmp r8d,eax / shl r8,2）
    static bool receipt_ok(const String &receipt, const String &expect);

    // 绑定点 0x39111B8，实现 0x3910070（184）
    // [确认] 0x8A2660 + 16 字符切片（r9d=0x10 / 0x895ED0）+ 比较
    static bool unseal_legacy_ok(const String &receipt);
};

}  // namespace xiewa

// =============================================================================
//  还原说明
//
// 1) 这些方法在二进制里不是"一整块代码"，而是一组 Variant 适配桩：
//    签名统一为 (Variant *ret, const Variant **args, int argc)，桩负责把
//    Variant 参数取成 String，再调系统 API 或内部实现，最后写回 ret。
//    所以上面的 C++ 签名是按适配桩的取参方式反推的，语义正确、类型标注偏保守。
//
// 2) 绑定机制（0x340C600）：
//    mov ecx,0x58; call 0x4198B50        ; 分配 MethodInfo（0x58 字节）
//    lea rax,[实现函数]; mov [rsi+0x48],rax
//    lea r9,[方法名]; mov rdx,rsi; call 0xCCE1A0   ; bind_methodfi（bind_method / bind_static_method 共用）
//    组B/组C 由 0x38F2A50 / 0x3910350 分别完成，结构同上。
//
//    ⚠ 2026-11-16 修正：这批方法在脚本侧是「类名.方法()」的**静态调用**，
//    运行时报 "Method is not static."（core/core_bind.cpp:1724，ClassDB::class_call_static
//    发现 MethodBind::is_static() == false）。原程序是把这些实现注册成静态方法的，
//    所以这里全部改用 ClassDB::bind_static_method(...)，C++ 侧对应 static 成员函数。
//    这些实现只读写文件级全局状态、从不访问 this，改成 static 不影响任何逻辑。
//
// 3) 辅助函数（同一模块内，非导出）：
//    0x2F37B0  String 赋值/拷贝（edx = 长度）
//    0x896840  String 由字面量赋值     0x896E90  String 由 String 赋值
//    0x8A65A0  String -> 宽字符        0x340F9F0 参数规范化 / Variant 拆箱为字符串
//    0x4198B50 / 0x4198B70 / 0x4198B30  operator new / new[] / operator delete
//    0x8942A0  String::String(name)    0x871790  ClassDB 注册模板内联
//
// 4) 还原状态（2026-11-16）：
//    - 54 个方法**全部**已有真实方法体，无伪代码、无空实现、无占位类型；
//      组A 在 xiewa_guard.cpp、组B 在 xiewa_guard_group_b.cpp、组C 在 xiewa_guard_group_c.cpp。
//    - 组A 21 条映射已整体纠正（旧表错位一位）；真体复核定案：
//      reg_erase(0x340F0F0 确实 RegDeleteValueW)、mutex_name(0x340F6A0 固定 GUID 字面量)、
//      is_release_template(返回 bool true)、flavor/vendor/reg_subkey/cache_dir 四串、
//      device_tag(1938 B) 与 pepper(461 B) 分体。
//    - 注释里 [确认] = 反汇编直接可见；[推定] = 形状已知、细节按最合理语义落地。
//    - 仍未闭环（不影响可编译性，只影响与原程序的逐字节等价）：
//      · configure_runtime_detection 的配置字典来源（pck 侧，本任务按用户要求只处理 exe）；
//      · bits 位图的位定义、Meta::digest_alt 的用途、read_embedded_stream 的流来源；
//      · 组B 第二套异或生成器的四张真表已取到摊平熵值，但表内轮转顺序未逐字节展开。
// =============================================================================
