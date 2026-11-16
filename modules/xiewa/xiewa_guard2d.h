// =============================================================================
//  xiewa_guard2d.h —— 与 xiewa_guard2d.cpp 配套的**可编译**头文件
//
//  ★ 本头是按 .cpp 的实际用法逐字段对齐写成的（旧"声明稿"已移入 _pseudo_backup）。
//    - 结构体字段全部按 C++ 标准成员声明，不再模拟原程序的裸偏移互读；
//    - 类型用引擎真实类型（String / Vector / Dictionary），无占位类型；
//    - 接口签名与 .cpp 的函数定义逐条一致。
//
//  对应原程序：0x3E09xxx–0x3E1495A 这一整块 PE 自校验代码
//    CurrentProcessReader 构造 0x3E0C910 / read 0x3E0EF00 / image_base 0x3E0F050
//    verify 0x3E0C980 / read_headers 0x3E0D3C0 / read_relocations 0x3E0D900
//    process_chunk 0x3E0E4C0 / read_embedded_stream 0x3E0E340 / to_hex 0x3E0ED70
//    meta_from_dictionary 0x38EBB10 / script_integrity 0x3E13260
// =============================================================================

#pragma once

#include <stdint.h>
#include <stddef.h>

#include "core/string/ustring.h"
#include "core/templates/vector.h"
#include "core/variant/dictionary.h"
#include "core/variant/variant.h"

namespace xiewa_guard2d {

// 方案标识（常量在 .cpp 里定义；这里只做声明，避免重复定义）
extern const char *const kSchemeTag;   // "pe-text-subtract-relocation-v1"
extern const char *const kMetadataTag; // "XIEWA-D4-PE-METADATA-v1"
extern const char *const kHexDigits;   // "0123456789abcdef"

// -----------------------------------------------------------------------------
// 一、CurrentProcessReader —— 读本进程已映射的镜像内存（不是磁盘文件）
//   原对象 16 字节：+0 vtable、+8 HMODULE
// -----------------------------------------------------------------------------
class CurrentProcessReader {
public:
	CurrentProcessReader();
	~CurrentProcessReader();

	// +0x08：GetModuleHandleW(nullptr)
	void *module = nullptr;

	// 0x3E0EF00：边界检查 → 逐段 VirtualQuery（必须是本模块、MEM_COMMIT、MEM_IMAGE、
	// 无 PAGE_NOACCESS|PAGE_GUARD）→ GetCurrentProcess + ReadProcessMemory
	bool read(uint32_t p_offset, size_t p_size, void *r_out) const;

	// 0x3E0F050：返回模块基址
	uint64_t image_base() const;

private:
	// 不可拷贝（内部缓存 module 指针）
	CurrentProcessReader(const CurrentProcessReader &);
	CurrentProcessReader &operator=(const CurrentProcessReader &);
};

// -----------------------------------------------------------------------------
// 二、Meta —— 脚本层传入的 integrity_baseline 子字典（U7 结论：不在 PE 内嵌）
// -----------------------------------------------------------------------------
struct Meta {
	uint32_t version = 1;
	String tag;                 // 必须 == kSchemeTag，长度 30
	uint16_t machine = 0;       // 0x8664(x64) / 0x14C(x86)
	uint32_t timestamp = 0;     // 0 表示不校验
	uint32_t size_of_image = 0;
	uint32_t text_rva = 0;
	uint32_t text_size = 0;
	uint64_t image_base = 0;    // 首选基址（算 delta 用）
	uint8_t digest_text[32] = { 0 }; // .text 归一化摘要
	uint8_t digest_alt[32] = { 0 };  // 第二摘要；全 0 表示不校验
};

// -----------------------------------------------------------------------------
// 三、PE 结构
// -----------------------------------------------------------------------------
struct Section {
	char name[9] = { 0 };       // 8 字节名 + 结尾
	uint32_t virtual_size = 0;
	uint32_t virtual_address = 0;
	uint32_t raw_size = 0;
	uint32_t raw_ptr = 0;
	uint32_t characteristics = 0;
};

struct ImageInfo {
	uint16_t machine = 0;
	uint16_t characteristics = 0;
	uint32_t timestamp = 0;
	uint32_t size_of_image = 0;
	uint32_t size_of_headers = 0;
	uint32_t text_rva = 0;       // .text 节 VirtualAddress（read_relocations/process_chunk 用）
	uint32_t text_raw_ptr = 0;
	uint32_t text_size = 0;      // max(VirtualSize, SizeOfRawData)
	uint32_t reloc_rva = 0;
	uint32_t reloc_size = 0;
	uint64_t opt_image_base = 0;
	int text_index = -1;
	Vector<Section> sections;
};

// 重定位项：目标 RVA + 参与减法的字节宽度（8 = DIR64，4 = HIGHLOW）
struct Reloc {
	uint32_t target = 0;
	uint8_t width = 4;
};

// -----------------------------------------------------------------------------
// 四、ImageState —— verify 的会话状态（字段按 .cpp 实际读写）
// -----------------------------------------------------------------------------
struct ImageState {
	CurrentProcessReader *reader = nullptr;
	void *owner = nullptr;
	ImageInfo info;
	uint64_t preferred_base = 0;

	Vector<Reloc> relocs;
	uint32_t reloc_index = 0;
	uint32_t chunk_offset = 0;
	Vector<uint8_t> chunk_buffer;

	uint32_t status = 0;
	uint32_t result_code = 4;   // 4 = 未初始化
	bool inited = false;
	bool verified = false;
	uint8_t digest[32] = { 0 };
	String error;
};

// -----------------------------------------------------------------------------
// 五、impl —— 与 .cpp 一致的自由函数接口
// -----------------------------------------------------------------------------
namespace impl {

bool read_headers(CurrentProcessReader *p_reader, ImageInfo &r_info, String &r_err);

bool read_relocations(CurrentProcessReader *p_reader, const ImageInfo &p_info,
		Vector<Reloc> &r_out, String &r_err);

bool process_chunk(ImageState *p_state, uint64_t p_offset, String &r_err);

bool verify(ImageState *p_state, CurrentProcessReader *p_reader, const Meta &p_meta, String &r_err);

bool read_embedded_stream(void *p_file_handle, Vector<uint8_t> &r_out, String &r_err);

String to_hex(const uint8_t p_in[32]);

bool meta_from_dictionary(const Dictionary &p_baseline, Meta &r_meta, String &r_err);

Dictionary script_integrity_impl(const Dictionary &p_config);

String last_error();

} // namespace impl

} // namespace xiewa_guard2d
