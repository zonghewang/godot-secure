// =============================================================================
//  XiewaCore.h  —— XiewaCore 类定义（声明级还原，非原创源码）
//  ★ 这是真正的 XiewaCore：抽象类，6 个 core_* 方法。
//    （此前误命名为 XiewaCore 的文件实为 XiewaGuard 组B，已改名 XiewaGuard_组B.*）
//
//  来源      : E:\gamezip\XiewaPai\XiewaPai.exe（SHA256 9AF23B57…B6081）
//  类名串    : 0x4B9AD5C；类名+方法名簇 0x50A35B8 起，顺序为
//              XiewaCore / core_version / core_selftest / core_sha256_hex /
//              core_shell / core_rpc / core_rules_selftest
//  注册      : 0x17ED380，register_abstract_class（class_db.h:0x113），父类 "Object"
//              类槽 0x5647840、父类槽 0x5646EE0、守卫字节 0x564783C
//  绑定      : XiewaCore::_bind_methods = 0x3412670（唯一调用者 0x17ED416）
//              MethodInfo 分配 0x50 字节（比 XiewaGuard 的 0x58 少 8）
//  绑定点    : 0x341279E / 0x34128DE / 0x3412A3A / 0x3412B7E / 0x3412CBE / 0x3412DEE
//  标注      : [确认] 反汇编直接可见   [推定] 由调用约定与上下文推断
//
//  说明：虽然以 register_abstract_class 注册，6 个方法**都有实体实现**，并非纯虚。
// =============================================================================

#pragma once

#include "core/object/object.h"
#include "core/variant/variant.h"

namespace xiewa {

class XiewaCore : public Object {
    GDCLASS(XiewaCore, Object);

protected:
    static void _bind_methods();   // 0x3412670

public:
    // 实现 0x3413190（`mov eax,7; ret`）
    // 核心版本号，常量 7。
    int core_version();

    // 实现 0x391A180（尾跳，303 指令）
    // 自检：算 hex(SHA-256("")) 并与常量
    //   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855（= SHA-256 空串）
    // 逐字节 memcmp(0x4198B60)，相等返回 1，否则 0。
    int core_selftest();

    // 实现 0x34131B0（72 指令）
    // 入参 String → SHA-256（0x39194E0）→ 分配 0x40 缓冲（0x35700）→
    // 用 "0123456789abcdef" 逐字节拼小写 hex → String::operator=(0x896840) 写回。
    String core_sha256_hex(const String &data);

    // 实现 0x3413300（15 指令）
    // 返回 6 字符字面量（RVA 0x4EA3615）。⚠ 实际取到 ".fDept"，语义未明，见 类全表 §6 U3。
    String core_shell();

    // 实现 0x3413340（0x188 栈帧，~600 指令）
    // 入参 String → 建 UTF-32 副本 → 0x3414B00 解析器 → 要求 token 类型 5 →
    // 跳过空白（位图 0x100002600）→ 取字段 fn / body / sig（0x34147E0）→
    // fn 长度 13 / 17 两路分支；17 字符 sig 与 .rdata 常量表异或后 ptest 全等；
    // 返回 JSON 串："{\"ok\":0,\"err\":\"sig\"}" / "{\"ok\":0,\"err\":\"…\"}" / "{\"ok\":1}"。
    String core_rpc(const String &envelope);

    // 实现 0x3927060（尾跳，~200 指令）
    // HMAC-SHA256 自检：key="Jefe"(len 4)、data="what do ya want for nothing?"(len 0x1C)
    //   → 0x391BD00 HMAC → hex → 与常量
    //   5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    //   （RFC 4231 Test Case 2 标准值）比较，相等返回 1，否则 0。
    int core_rules_selftest();
};

}  // namespace xiewa

// =============================================================================
//  还原说明
//
//  1) 类以 register_abstract_class 注册，父类写的是 "Object"（0x17ED4D0 处 lea rdx,"Object"）。
//     注册路径里还有一处静态初始化登记：0x17ED3D0 lea rcx,[0x563D3B8] / call 0x4199970
//     （atexit 风格），以及 TLS 存在性检查（0x5477024 / gs:[0x58]）。
//
//  2) 方法名簇 0x50A35B8 之后紧跟的串不是方法名，而是 core_rpc 的字段与返回模板：
//     module / rules_load_signed / sig / {"ok":0,"err":"sig"} / {"ok":0,"err":"…"} /
//     {"ok":1} / rng_test_seed / release / qa / {"ok":0,"err":"not_qa"} / test_block /
//     true / false / null / vector / %.17g / -----BEGIN PUBLIC KEY-----\nM…
//     其中 PEM 公钥（-----BEGIN PUBLIC KEY-----）疑为 core_rpc 的签名校验素材
//     （与组B verify2 的"非 RSA"结论并不矛盾：这里可能只是把它当字符串透传/展示）。
//
//  3) 未完成：
//     - core_rpc 的 13 / 17 两路分支各自完整语义、解析器 0x3414B00 的文法未展开；
//     - 17 字符 sig 的异或常量表（0x50A358F / 0x50A359F）与相邻浮点常量 1.0 重叠，待复核；
//     - core_shell 的字面量语义未解。
// =============================================================================
