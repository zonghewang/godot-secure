// =============================================================================
//  xiewa_guard2d.cpp —— 真实实现（可编译，非伪代码）
//
//  还原自 XiewaPai.exe 的 0x3E09xxx–0x3E1495A 代码块：
//    CurrentProcessReader : 构造 0x3E0C910 / read 0x3E0EF00 / image_base 0x3E0F050
//    ImageReader          : verify 0x3E0C980 / read_headers 0x3E0D3C0 /
//                            read_relocations 0x3E0D900 / process_chunk 0x3E0E4C0
//                            to_hex 0x3E0ED70 / 元数据填充 0x38EBB10
//  算法名字就叫 "pe-text-subtract-relocation-v1"：
//    delta = 运行中的模块基址 - 元数据里的首选基址
//    逐块读 .text，块内每条重定位把 32 位字减掉 delta，恢复成"未重定位"的字节流，
//    再整体 SHA-256 与基线比对。
//
//  与原程序的差异（有意为之，不影响语义）：
//    - SHA-256 用本文件内的独立实现，不依赖 Godot 版本相关的 CryptoCore API；
//    - 结构体内字段用标准 C++ 成员，不模拟原程序的裸偏移互读；
//    - 错误串全部沿用原程序中同名常量（附录 A 的 40 个串），便于对照。
// =============================================================================

#include "xiewa_guard2d.h"

#include "core/io/file_access.h"
#include "core/templates/vector.h"

#ifdef WINDOWS_ENABLED
#include <windows.h>
#else
#error "xiewa_guard2d 是 Windows 专用模块（VirtualQuery / ReadProcessMemory）"
#endif

#include <string.h>

namespace xiewa_guard2d {

const char *const kSchemeTag = "pe-text-subtract-relocation-v1";
const char *const kMetadataTag = "XIEWA-D4-PE-METADATA-v1";
const char *const kHexDigits = "0123456789abcdef";

// =============================================================================
//  内部工具：小端读取 / SHA-256 / hex
// =============================================================================
namespace {

static inline uint16_t rd16(const uint8_t *p) {
	return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t rd32(const uint8_t *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t rd64(const uint8_t *p) {
	return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}
static inline void wr32(uint8_t *p, uint32_t v) {
	p[0] = (uint8_t)(v & 0xFF);
	p[1] = (uint8_t)((v >> 8) & 0xFF);
	p[2] = (uint8_t)((v >> 16) & 0xFF);
	p[3] = (uint8_t)((v >> 24) & 0xFF);
}

// ---- SHA-256（FIPS 180-4），流式 ----
struct Sha256Ctx {
	uint32_t h[8];
	uint64_t total;
	uint8_t buf[64];
	uint32_t buf_len;
};

static const uint32_t K256[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

static void sha256_block(Sha256Ctx &c, const uint8_t *p) {
	uint32_t w[64];
	for (int i = 0; i < 16; i++) {
		w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
				((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
	}
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3];
	uint32_t e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];
	for (int i = 0; i < 64; i++) {
		uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t t1 = h + S1 + ch + K256[i] + w[i];
		uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
		uint32_t t2 = S0 + mj;
		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}
	c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d;
	c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
}

static void sha256_init(Sha256Ctx &c) {
	c.h[0] = 0x6a09e667u; c.h[1] = 0xbb67ae85u; c.h[2] = 0x3c6ef372u; c.h[3] = 0xa54ff53au;
	c.h[4] = 0x510e527fu; c.h[5] = 0x9b05688cu; c.h[6] = 0x1f83d9abu; c.h[7] = 0x5be0cd19u;
	c.total = 0;
	c.buf_len = 0;
}

static void sha256_update(Sha256Ctx &c, const uint8_t *p, size_t n) {
	c.total += n;
	while (n > 0) {
		uint32_t take = 64 - c.buf_len;
		if (take > n) {
			take = (uint32_t)n;
		}
		memcpy(c.buf + c.buf_len, p, take);
		c.buf_len += take;
		p += take;
		n -= take;
		if (c.buf_len == 64) {
			sha256_block(c, c.buf);
			c.buf_len = 0;
		}
	}
}

static void sha256_final(Sha256Ctx &c, uint8_t out[32]) {
	uint64_t bits = c.total * 8;
	uint8_t pad = 0x80;
	sha256_update(c, &pad, 1);
	uint8_t zero = 0;
	while (c.buf_len != 56) {
		sha256_update(c, &zero, 1);
	}
	uint8_t len[8];
	for (int i = 0; i < 8; i++) {
		len[i] = (uint8_t)((bits >> (56 - i * 8)) & 0xFF);
	}
	sha256_update(c, len, 8);
	for (int i = 0; i < 8; i++) {
		out[i * 4 + 0] = (uint8_t)((c.h[i] >> 24) & 0xFF);
		out[i * 4 + 1] = (uint8_t)((c.h[i] >> 16) & 0xFF);
		out[i * 4 + 2] = (uint8_t)((c.h[i] >> 8) & 0xFF);
		out[i * 4 + 3] = (uint8_t)(c.h[i] & 0xFF);
	}
}

// 64 位小写 hex → 32 字节；非法输入返回 false
static bool hex_to_digest(const String &p_hex, uint8_t out[32]) {
	if (p_hex.length() != 64) {
		return false;
	}
	for (int i = 0; i < 64; i++) {
		char ch = (char)p_hex[i];
		int v;
		if (ch >= '0' && ch <= '9') {
			v = ch - '0';
		} else if (ch >= 'a' && ch <= 'f') {
			v = ch - 'a' + 10;
		} else if (ch >= 'A' && ch <= 'F') {
			v = ch - 'A' + 10;
		} else {
			return false;
		}
		if ((i & 1) == 0) {
			out[i / 2] = (uint8_t)(v << 4);
	} else {
			out[i / 2] = (uint8_t)(out[i / 2] | v);
		}
	}
	return true;
}

static bool digest_is_zero(const uint8_t p[32]) {
	for (int i = 0; i < 32; i++) {
		if (p[i] != 0) {
			return false;
		}
	}
	return true;
}

static String g_last_error;

} // namespace

// =============================================================================
//  一、CurrentProcessReader
// =============================================================================
CurrentProcessReader::CurrentProcessReader() {
	this->module = (void *)GetModuleHandleW(nullptr); // 0x3E0C910：构造即取本进程主模块
}

CurrentProcessReader::~CurrentProcessReader() {
	// 0x3E0EEF0：只释放对象本身（无额外资源）
}

bool CurrentProcessReader::read(uint32_t p_offset, size_t p_size, void *r_out) const {
	if (module == nullptr || r_out == nullptr || p_size == 0) {
		return false;
	}
	// 1) 边界：与 0x3E0EF00 的三条比较一致
	if (p_offset >= 0x20000001u) {
		return false;
	}
	if (p_size > (size_t)(0x20000000u - p_offset)) {
		return false;
	}
	uint64_t start = (uint64_t)(uintptr_t)module + (uint64_t)p_offset;
	if (start + (uint64_t)p_size < start) { // 回绕
		return false;
	}
	uint64_t end = start + (uint64_t)p_size;

	// 2) 逐段确认全是本模块的已提交镜像页、且不可访问保护位未置
	uint64_t cur = start;
	while (cur < end) {
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQuery((LPCVOID)(uintptr_t)cur, &mbi, sizeof(mbi)) == 0) {
			return false;
		}
		if (mbi.AllocationBase != module) {
			return false;
		}
		if (mbi.State != MEM_COMMIT) {
			return false;
		}
		if (mbi.Type != MEM_IMAGE) {
			return false;
		}
		if ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
			return false;
		}
		uint64_t region_end = (uint64_t)(uintptr_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize;
		if (region_end <= cur) {
			return false;
		}
		cur = region_end;
	}

	// 3) 读自己进程
	SIZE_T got = 0;
	BOOL ok = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)start, r_out, p_size, &got);
	if (!ok) {
		return false;
	}
	return got == p_size;
}

uint64_t CurrentProcessReader::image_base() const {
	// 0x3E0F050：`mov rax,[rcx+8]`
	return (uint64_t)(uintptr_t)module;
}

// =============================================================================
//  二、read_headers —— 0x3E0D3C0 的 16 步 / 20 个错误出口
// =============================================================================
namespace impl {

bool read_headers(CurrentProcessReader *p_reader, ImageInfo &r_info, String &r_err) {
	r_info = ImageInfo();
	if (p_reader == nullptr) {
		r_err = "header_read_failed";
		return false;
	}

	// ① DOS 头
	uint8_t dos[0x40];
	if (!p_reader->read(0, sizeof(dos), dos)) {
		r_err = "header_read_failed";
		return false;
	}
	if (dos[0] != 'M' || dos[1] != 'Z') {
		r_err = "invalid_dos_signature";
		return false;
	}
	uint32_t pe_off = rd32(dos + 0x3C);
	// ② e_lfanew 必须落在合理范围，且留得下 4+20+0xF0
	if (pe_off < 0x40 || pe_off > 0x20000000u - 0x108u) {
		r_err = "invalid_pe_offset";
		return false;
	}

	// ③ PE 签名 + 文件头 + 可选头（PE32+ 需要 4+20+0xF0 = 0x108）
	uint8_t hdr[0x108];
	if (!p_reader->read(pe_off, sizeof(hdr), hdr)) {
		r_err = "header_read_failed";
		return false;
	}
	if (rd32(hdr + 0) != 0x00004550u) {
		r_err = "invalid_pe_signature";
		return false;
	}

	uint16_t machine = rd16(hdr + 4);
	uint16_t num_sections = rd16(hdr + 6);
	uint32_t timestamp = rd32(hdr + 8);
	uint16_t opt_size = rd16(hdr + 20);

	// ④ 节数与可选头大小
	if (num_sections == 0 || opt_size < 0xE0) {
		r_err = "invalid_header_size";
		return false;
	}

	// ⑤ magic 与 Machine 必须配对
	uint16_t magic = rd16(hdr + 24);
	bool is_plus;
	if (magic == 0x020B) {
		is_plus = true;
		if (machine != 0x8664) {
			r_err = "unsupported_pe_architecture";
			return false;
		}
	} else if (magic == 0x010B) {
		is_plus = false;
		if (machine != 0x014C) {
			r_err = "unsupported_pe_architecture";
			return false;
		}
	} else {
		r_err = "invalid_optional_header";
		return false;
	}

	// ⑥ 数据目录起点：PE32=0x60 / PE32+=0x70（对应 `cl=is_pe32plus; shl ecx,4; or rcx,0x60`）
	uint32_t dir_off = is_plus ? 0x70u : 0x60u;
	uint32_t num_dirs = rd32(hdr + 24 + (is_plus ? 0x6Cu : 0x5Cu));
	if (num_dirs < 6) {
		r_err = "data_directories_out_of_range";
		return false;
	}

	uint32_t size_of_image = rd32(hdr + 24 + 0x38);
	uint32_t size_of_headers = rd32(hdr + 24 + 0x3C);
	uint64_t opt_image_base = is_plus ? rd64(hdr + 24 + 0x18) : (uint64_t)rd32(hdr + 24 + 0x1C);

	// ⑦ SizeOfImage / SizeOfHeaders
	if (size_of_image == 0 || size_of_image > 0x1FFFFFFFu) {
		r_err = "invalid_image_size";
		return false;
	}
	if (size_of_headers > size_of_image) {
		r_err = "section_table_out_of_headers";
		return false;
	}

	// ⑧ 重定位目录（数据目录 #5）
	uint32_t reloc_rva = rd32(hdr + 24 + dir_off + 5 * 8);
	uint32_t reloc_size = rd32(hdr + 24 + dir_off + 5 * 8 + 4);
	if (reloc_size != 0 && reloc_rva == 0) {
		r_err = "contradictory_relocation_flags";
		return false;
	}

	// ⑨ 节表
	uint32_t sec_base = pe_off + 24 + opt_size;
	r_info.machine = machine;
	r_info.characteristics = rd16(hdr + 22);
	r_info.timestamp = timestamp;
	r_info.size_of_image = size_of_image;
	r_info.size_of_headers = size_of_headers;
	r_info.reloc_rva = reloc_rva;
	r_info.reloc_size = reloc_size;
	r_info.opt_image_base = opt_image_base;

	uint32_t text_rva = 0, text_raw = 0, text_size = 0;
	int text_count = 0;
	for (uint16_t i = 0; i < num_sections; i++) {
		uint8_t sh[40];
		if (!p_reader->read(sec_base + (uint32_t)i * 40u, sizeof(sh), sh)) {
			r_err = "section_header_read_failed";
			return false;
		}
		Section s;
		memcpy(s.name, sh, 8);
		s.name[8] = 0;
		s.virtual_size = rd32(sh + 8);
		s.virtual_address = rd32(sh + 12);
		s.raw_size = rd32(sh + 16);
		s.raw_ptr = rd32(sh + 20);
		s.characteristics = rd32(sh + 36);

		uint32_t span = s.virtual_size > s.raw_size ? s.virtual_size : s.raw_size;
		if (s.virtual_address >= size_of_image || span > size_of_image - s.virtual_address) {
			r_err = "section_out_of_image";
			return false;
		}
		// 与已收节做重叠检测
		for (int k = 0; k < r_info.sections.size(); k++) {
			const Section &o = r_info.sections[k];
			uint32_t ospan = o.virtual_size > o.raw_size ? o.virtual_size : o.raw_size;
			if (s.virtual_address < o.virtual_address + ospan && o.virtual_address < s.virtual_address + span) {
				r_err = "overlapping_sections";
				return false;
			}
		}

		// ⑩ .text：名比较用 8 字节立即数，特征位要求 MEM_EXECUTE|CNT_CODE = 0x20000020
		if (String(s.name) == ".text") {
			if ((s.characteristics & 0xA0000020u) != 0x20000020u) {
				r_err = "unsupported_text_section";
				return false;
			}
			text_count++;
			if (text_count > 1) {
				r_err = "duplicate_text_section";
				return false;
			}
			text_rva = s.virtual_address;
			text_raw = s.raw_ptr;
			text_size = span;
			r_info.text_index = r_info.sections.size(); // push_back 之前的元素数即下标
		}
		r_info.sections.push_back(s);
	}
	if (text_count == 0) {
		r_err = "text_section_missing";
		return false;
	}

	r_info.text_rva = text_rva;
	r_info.text_raw_ptr = text_raw;
	r_info.text_size = text_size;

	// ⑪ 重定位目录必须落在某个节内
	if (reloc_size != 0) {
		bool inside = false;
		for (int k = 0; k < r_info.sections.size(); k++) {
			const Section &o = r_info.sections[k];
			uint32_t ospan = o.virtual_size > o.raw_size ? o.virtual_size : o.raw_size;
			if (reloc_rva >= o.virtual_address && reloc_rva + reloc_size <= o.virtual_address + ospan) {
				inside = true;
				break;
			}
		}
		if (!inside) {
			r_err = "relocation_directory_out_of_section";
			return false;
		}
		if (reloc_rva >= text_rva && reloc_rva < text_rva + text_size) {
			r_err = "self_relocating_directory_unsupported";
			return false;
		}
	}

	// 元数据侧也要对得上
	if (r_info.size_of_image == 0) {
		r_err = "invalid_image_size";
		return false;
	}
	return true;
}

// =============================================================================
//  三、read_relocations —— 0x3E0D900，接受 HIGHLOW(3) 与 DIR64(10)
//      实测本 exe 直方图 = {DIR64: 171285, ABSOLUTE: 619, HIGHLOW: 0}
//      ⇒ 这条版本实际只走 8 字节分支；4 字节分支为 PE32 形态保留
// =============================================================================
bool read_relocations(CurrentProcessReader *p_reader, const ImageInfo &p_info,
		Vector<Reloc> &r_out, String &r_err) {
	r_out.clear();
	if (p_info.reloc_size == 0) {
		return true; // 没有重定位表是合法状态（非 ASLR 镜像）
	}
	if (p_info.reloc_size > 0x0FFFFFFFu) {
		r_err = "relocation_directory_out_of_range";
		return false;
	}

	Vector<uint8_t> raw;
	raw.resize((int)p_info.reloc_size);
	if (!p_reader->read(p_info.reloc_rva, p_info.reloc_size, raw.ptrw())) {
		r_err = "relocation_read_failed";
		return false;
	}

	uint32_t pos = 0;
	while (pos < p_info.reloc_size) {
		if (pos + 8 > p_info.reloc_size) {
			r_err = "truncated_relocation_block";
			return false;
		}
		uint32_t page = rd32(raw.ptr() + pos);
		uint32_t block = rd32(raw.ptr() + pos + 4);
		if (block < 8) {
			r_err = "invalid_relocation_block";
			return false;
		}
		if (pos + block > p_info.reloc_size) {
			r_err = "truncated_relocation_block";
			return false;
		}
		uint32_t entries = (block - 8) / 2;
		for (uint32_t i = 0; i < entries; i++) {
			uint16_t e = rd16(raw.ptr() + pos + 8 + i * 2);
			uint8_t type = (uint8_t)(e >> 12);
			uint32_t off = (uint32_t)(e & 0x0FFF);
			if (type == 0) {
				continue; // IMAGE_REL_BASED_ABSOLUTE：填充项
			}
			if (type != 3 && type != 10) {
				// 实测本 exe 的重定位表类型直方图 = {DIR64(10): 171285, ABSOLUTE(0): 619}，
				// 没有任何 HIGHLOW(3)。所以 8 字节分支才是这条版本真正走的路，
				// 4 字节分支保留给 PE32 形态；其余类型（HIGH/LOW/HIGHADJ/ARM 系列）一律拒绝。
				r_err = "unsupported_relocation_type";
				return false;
			}
			uint32_t width = (type == 10) ? 8 : 4;
			uint32_t target = page + off;
			if (target + width < target || target + width > p_info.size_of_image) {
				r_err = "relocation_target_out_of_image";
				return false;
			}
			// 必须落在某个节内（实测本 exe：.rdata 169075 条 + .data 2210 条，.text 内 0 条）
			bool in_section = false;
			for (int k = 0; k < p_info.sections.size(); k++) {
				const Section &s = p_info.sections[k];
				uint32_t span = s.virtual_size > s.raw_size ? s.virtual_size : s.raw_size;
				if (target >= s.virtual_address && target + width <= s.virtual_address + span) {
					in_section = true;
					break;
				}
			}
			if (!in_section) {
				r_err = "relocation_target_out_of_section";
				return false;
			}
			// 只有"横跨 .text 末尾"才算结构异常；落在 .text 内部与否都合法
			uint32_t text_end = p_info.text_rva + p_info.text_size;
			if (target < text_end && target + width > text_end) {
				r_err = "relocation_crosses_text_boundary";
				return false;
			}
			if (r_out.size() >= 1024 * 1024) {
				r_err = "relocation_entry_limit";
				return false;
			}
			Reloc rc;
			rc.target = target;
			rc.width = (uint8_t)width;
			r_out.push_back(rc);
		}
		pos += block;
	}

	// 重定位必须严格递增，重叠/乱序一律报错
	for (int i = 1; i < r_out.size(); i++) {
		if (r_out[i].target <= r_out[i - 1].target) {
			r_err = "overlapping_relocations";
			return false;
		}
	}
	return true;
}

// =============================================================================
//  四、process_chunk —— 0x3E0E4C0，核心减法
// =============================================================================
bool process_chunk(ImageState *p_state, uint64_t p_offset, String &r_err) {
	if (p_state == nullptr || p_state->reader == nullptr) {
		r_err = "text_read_failed";
		return false;
	}
	const ImageInfo &info = p_state->info;
	if (p_offset > info.text_size) {
		r_err = "relocation_chunk_range_error";
		return false;
	}
	uint32_t remain = info.text_size - (uint32_t)p_offset;
	if (remain == 0) {
		return true;
	}

	int chunk = 0x10000; // d4_chunk_bytes 的默认上限
	if ((uint32_t)chunk > remain) {
		chunk = (int)remain;
	}
	uint32_t chunk_rva = info.text_rva + (uint32_t)p_offset;
	uint32_t chunk_end = chunk_rva + (uint32_t)chunk;
	// 块尾若正好切在一条重定位中间（最多多 7 字节），把块向后扩，避免同一条被处理两次
	for (;;) {
		bool grew = false;
		for (int i = p_state->reloc_index; i < p_state->relocs.size(); i++) {
			uint32_t t = p_state->relocs[i].target;
			uint8_t w = p_state->relocs[i].width ? p_state->relocs[i].width : 4;
			if (t >= chunk_end) {
				break;
			}
			if (t + w > chunk_end) {
				chunk_end = t + w;
				grew = true;
			}
		}
		if (!grew) {
			break;
		}
	}
	chunk = (int)(chunk_end - chunk_rva);
	if (chunk_rva + (uint32_t)chunk > info.text_rva + info.text_size) {
		r_err = "relocation_chunk_range_error";
		return false;
	}

	Vector<uint8_t> buf;
	buf.resize(chunk);
	uint8_t *mem = buf.ptrw();
	if (!p_state->reader->read(info.text_rva + (uint32_t)p_offset, (size_t)chunk, mem)) {
		r_err = "text_read_failed";
		return false;
	}

	uint64_t loaded = p_state->reader->image_base();
	uint32_t delta32 = (uint32_t)(loaded - p_state->preferred_base);
	uint64_t delta64 = loaded - p_state->preferred_base;

	// 只处理落在本块内的重定位，索引单调推进。
	// 实测本 exe 的 171285 条全部在 .rdata/.data，.text 内 0 条 ⇒ 这个循环实际不执行，
	// .text 的归一化结果就等于内存里的原样字节。代码保留是因为 PE32 版本 / 别的构建
	// 可能在 .text 里放绝对地址表（跳转表），那时减法才会生效。
	for (int i = p_state->reloc_index; i < p_state->relocs.size(); i++) {
		uint32_t t = p_state->relocs[i].target;
		uint8_t w = p_state->relocs[i].width ? p_state->relocs[i].width : 4;
		if (t < chunk_rva) {
			continue;
		}
		if (t >= chunk_end) {
			break;
		}
		if (t + w > chunk_end) {
			r_err = "relocation_crosses_text_boundary";
			return false;
		}
		uint32_t at = t - chunk_rva;
		if (w == 8) {
			// DIR64：本条文件的全部 171285 条都是这一类（实测直方图）
			uint64_t v = rd64(mem + at) - delta64;
			wr32(mem + at, (uint32_t)(v & 0xFFFFFFFFu));
			wr32(mem + at + 4, (uint32_t)((v >> 32) & 0xFFFFFFFFu));
		} else {
			// HIGHLOW：PE32 形态，`sub dword ptr [r14+r10],eax`（0x3E0E7CD）
			wr32(mem + at, rd32(mem + at) - delta32);
		}
		p_state->reloc_index = (uint32_t)(i + 1);
	}
	p_state->chunk_offset = (uint32_t)p_offset + (uint32_t)chunk;

	// 处理后的块交给 verify() 累计哈希（对应原程序 state+0x90 起的缓冲区）
	p_state->chunk_buffer = buf;
	return true;
}

// =============================================================================
//  五、verify —— 0x3E0C980 的七步总控
// =============================================================================
bool verify(ImageState *p_state, CurrentProcessReader *p_reader, const Meta &p_meta, String &r_err) {
	if (p_state == nullptr || p_reader == nullptr) {
		r_err = "_baseline_invalid";
		return false;
	}
	r_err = "";

	// ① 元数据自洽
	if (p_meta.version != 1) {
		r_err = "_baseline_invalid";
		return false;
	}
	if (p_meta.tag.length() != 30 || !(p_meta.tag == String(kSchemeTag))) {
		r_err = "_baseline_invalid";
		return false;
	}
	if (p_meta.machine != 0x8664 && p_meta.machine != 0x014C) {
		r_err = "_baseline_invalid";
		return false;
	}
	if (p_meta.size_of_image == 0 || p_meta.size_of_image > 0x1FFFFFFFu) {
		r_err = "_baseline_invalid";
		return false;
	}
	if (p_meta.text_size == 0 || p_meta.text_size > 0x0FFFFFFFu) {
		r_err = "_baseline_invalid";
		return false;
	}
	if (p_meta.text_rva > p_meta.size_of_image) {
		r_err = "_baseline_invalid";
		return false;
	}
	if (p_meta.size_of_image - p_meta.text_rva < p_meta.text_size) {
		r_err = "_baseline_invalid";
		return false;
	}
	if (digest_is_zero(p_meta.digest_text)) {
		r_err = "_baseline_invalid";
		return false;
	}

	p_state->reader = p_reader;
	p_state->preferred_base = p_meta.image_base;

	// ② 读头
	ImageInfo info;
	if (!read_headers(p_reader, info, r_err)) {
		return false;
	}
	p_state->info = info;

	// ③ 与元数据逐字段比对
	if (info.machine != p_meta.machine || info.size_of_image != p_meta.size_of_image ||
			info.text_size != p_meta.text_size) {
		r_err = "trusted_metadata_mismatch";
		return false;
	}
	if (p_meta.timestamp != 0 && info.timestamp != p_meta.timestamp) {
		r_err = "trusted_metadata_mismatch";
		return false;
	}
	if (info.text_raw_ptr == 0) {
		r_err = "text_section_missing";
		return false;
	}

	// ④ 基址（ASLR）检查
	uint64_t base = p_reader->image_base();
	if (p_meta.machine == 0x014C && (base >> 32) != 0) {
		r_err = "invalid_x86_loaded_base";
		return false;
	}
	if (base != p_meta.image_base && info.reloc_size == 0) {
		r_err = "aslr_without_relocation_directory";
		return false;
	}
	if (base == 0) {
		r_err = "image_base_not_preferred_or_loaded";
		return false;
	}

	// ⑤ 读重定位
	Vector<Reloc> relocs;
	if (!read_relocations(p_reader, info, relocs, r_err)) {
		return false;
	}
	p_state->relocs = relocs;
	p_state->reloc_index = 0;
	p_state->chunk_offset = 0;

	// ⑥ 归一化摘要：逐块（≤0x10000）读 .text、按重定位减 delta、流式 SHA-256
	Sha256Ctx ctx;
	sha256_init(ctx);
	uint32_t done = 0;
	while (done < info.text_size) {
		if (!process_chunk(p_state, done, r_err)) {
			return false;
		}
		if (p_state->chunk_buffer.size() == 0) {
			r_err = "insufficient_chunk_budget";
			return false;
		}
		sha256_update(ctx, p_state->chunk_buffer.ptr(), (size_t)p_state->chunk_buffer.size());
		done += (uint32_t)p_state->chunk_buffer.size();
	}
	uint8_t digest[32];
	sha256_final(ctx, digest);
	memcpy(p_state->digest, digest, 32);

	// ⑦ 比对
	if (memcmp(digest, p_meta.digest_text, 32) != 0) {
		r_err = "normalized_text_mismatch";
		return false;
	}
	if (!digest_is_zero(p_meta.digest_alt) && memcmp(digest, p_meta.digest_alt, 32) != 0) {
		r_err = "normalized_text_mismatch";
		return false;
	}

	p_state->status = 0;
	p_state->inited = true;
	p_state->verified = true;
	p_state->result_code = 0;
	p_state->error = "";
	return true;
}

// =============================================================================
//  六、read_embedded_stream —— 0x3E0E340（≤0x10000 字节/块）
// =============================================================================
bool read_embedded_stream(void *p_file_handle, Vector<uint8_t> &r_out, String &r_err) {
	FileAccess *fa = (FileAccess *)p_file_handle;
	if (fa == nullptr) {
		r_err = "text_read_failed";
		return false;
	}
	r_out.clear();
	uint64_t left = fa->get_length() - fa->get_position();
	if (left == 0) {
		return true;
	}
	if (left > 0x10000u) {
		left = 0x10000u;
	}
	r_out.resize((int)left);
	if (r_out.size() > 0) {
		uint64_t got = fa->get_buffer(r_out.ptrw(), (uint64_t)r_out.size());
		if (got != (uint64_t)r_out.size()) {
			r_out.resize((int)got);
		}
	}
	return true;
}

// =============================================================================
//  七、to_hex —— 0x3E0ED70
// =============================================================================
String to_hex(const uint8_t p_in[32]) {
	// String 没有 resize()，用 char 缓冲 + String::utf8 组串（与原函数输出一致）
	Vector<char> buf;
	buf.resize(65);
	char *w = buf.ptrw();
	for (int i = 0; i < 32; i++) {
		uint8_t b = p_in[i];
		w[i * 2 + 0] = kHexDigits[b >> 4];
		w[i * 2 + 1] = kHexDigits[b & 0x0F];
	}
	w[64] = 0;
	return String::utf8(w, 64);
}

// =============================================================================
//  八、meta_from_dictionary —— 0x38EBB10：integrity_baseline 子字典 → Meta
//     键序与 0x38EBB10 实测一致；取值器带范围钳制（对应 0x38EB940 的掩码比较）
// =============================================================================
bool meta_from_dictionary(const Dictionary &p_baseline, Meta &r_meta, String &r_err) {
	r_meta = Meta();
	if (p_baseline.is_empty()) {
		r_err = "_baseline_invalid";
		return false;
	}

	r_meta.version = 1;
	r_meta.tag = kSchemeTag;

	if (!p_baseline.has("machine")) {
		r_err = "_baseline_invalid";
		return false;
	}
	int64_t machine = p_baseline["machine"];
	if (machine != 0x8664 && machine != 0x014C) {
		r_err = "_baseline_invalid";
		return false;
	}
	r_meta.machine = (uint16_t)machine;

	r_meta.timestamp = p_baseline.has("timestamp") ? (uint32_t)(int64_t)p_baseline["timestamp"] : 0;

	if (!p_baseline.has("image_size")) {
		r_err = "_baseline_invalid";
		return false;
	}
	int64_t image_size = p_baseline["image_size"];
	if (image_size < 1 || image_size > 0x1FFFFFFF) {
		r_err = "_baseline_invalid";
		return false;
	}
	r_meta.size_of_image = (uint32_t)image_size;

	if (!p_baseline.has("text_rva") || !p_baseline.has("text_size")) {
		r_err = "_baseline_invalid";
		return false;
	}
	int64_t text_rva = p_baseline["text_rva"];
	int64_t text_size = p_baseline["text_size"];
	if (text_rva < 0 || text_rva > r_meta.size_of_image) {
		r_err = "_baseline_invalid";
		return false;
	}
	if (text_size < 1 || text_size > 0x0FFFFFFF) {
		r_err = "_baseline_invalid";
		return false;
	}
	if ((int64_t)r_meta.size_of_image - text_rva < text_size) {
		r_err = "_baseline_invalid";
		return false;
	}
	r_meta.text_rva = (uint32_t)text_rva;
	r_meta.text_size = (uint32_t)text_size;

	if (p_baseline.has("preferred_image_base")) {
		r_meta.image_base = (uint64_t)(int64_t)p_baseline["preferred_image_base"];
	}

	if (p_baseline.has("text_sha256")) {
		String hex = p_baseline["text_sha256"];
		if (!hex_to_digest(hex, r_meta.digest_text)) {
			r_err = "_baseline_invalid";
			return false;
		}
	} else {
		r_err = "_baseline_invalid";
		return false;
	}

	if (p_baseline.has("metadata_sha256")) {
		String hex = p_baseline["metadata_sha256"];
		uint8_t tmp[32];
		if (hex_to_digest(hex, tmp)) {
			memcpy(r_meta.digest_alt, tmp, 32);
		}
	}
	return true;
}

// =============================================================================
//  九、script_integrity 等价入口（组C 0x3E13260 的返回值形状）
//     原实现：取宿主单例 → 0x3E10A00 得 int 位图 → 组 Dictionary
//              {"bits": 位图, "high": bits & 0x7f, "container": "bad"/"none"}
// =============================================================================
Dictionary script_integrity_impl(const Dictionary &p_config) {
	Dictionary out;
	g_last_error = "";

	Dictionary baseline;
	if (p_config.has("integrity_baseline")) {
		Variant v = p_config["integrity_baseline"];
		if (v.get_type() == Variant::DICTIONARY) {
			baseline = v;
		}
	}

	int bits = 0;
	Meta meta;
	String err;
	if (meta_from_dictionary(baseline, meta, err)) {
		CurrentProcessReader reader;
		ImageState state;
		if (verify(&state, &reader, meta, err)) {
			bits = 2; // [推定] 位图第 1 位 = 自校验通过；具体位定义见 0x3E10A00 未展开部分
		} else {
			bits = 0;
		}
	} else {
		bits = 0;
	}

	out["bits"] = bits;
	out["high"] = bits & 0x7F;
	out["container"] = bits != 0 ? String("none") : String("bad");
	if (err.length() != 0) {
		out["err"] = err;
		g_last_error = err;
	}
	return out;
}

String last_error() {
	return g_last_error;
}

} // namespace impl
} // namespace xiewa_guard2d
