#include "core.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <stdint.h>

#include "Zydis.h"
#include "blob.h"

namespace sse42 {

namespace {

const char SECNAME[8] = {'.', 's', 's', 'e', '4', '2', 'e', 'm'};

template <typename T>
T rd(const std::vector<uint8_t>& b, size_t off) {
    T v;
    std::memcpy(&v, b.data() + off, sizeof(T));
    return v;
}
template <typename T>
void wr(std::vector<uint8_t>& b, size_t off, T v) {
    std::memcpy(b.data() + off, &v, sizeof(T));
}
static inline uint32_t alignUp(uint32_t v, uint32_t a) {return (v+a-1)/a*a;}

std::string sfmt(const char* f, ...) __attribute__((format(printf, 1, 2)));
std::string sfmt(const char* f, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, f);
    vsnprintf(buf, sizeof buf, f, ap);
    va_end(ap);
    return buf;
}

struct Section {
    char name[9];
    uint32_t vsize, va, rawsize, rawptr, chars;
    size_t hdrOff;
};

struct PE {
    const std::vector<uint8_t>* img = nullptr;
    size_t ntOff = 0, fileHdrOff = 0, optOff = 0, secTableOff = 0;
    uint16_t numSections = 0, sizeOfOpt = 0;
    uint32_t sectionAlign = 0, fileAlign = 0, sizeOfHeaders = 0;
    std::vector<Section> secs;

    size_t dataDirOff(int i) const { return optOff + 112 + 8 * i; }
    uint32_t dirRva(int i) const { return rd<uint32_t>(*img, dataDirOff(i)); }
    uint32_t dirSize(int i) const { return rd<uint32_t>(*img, dataDirOff(i) + 4); }

    const Section* secOf(uint32_t rva) const {
        for (auto& s : secs) {
            uint32_t span = std::max(s.vsize, s.rawsize);
            if (rva >= s.va && rva < s.va + span) return &s;
        }
        return nullptr;
    }

    size_t off(uint32_t rva) const {
        const Section* s = secOf(rva);
        if (!s || rva - s->va >= s->rawsize) return SIZE_MAX;
        return s->rawptr + (rva - s->va);
    }
};

bool readPE(const std::vector<uint8_t>& b, PE& pe, std::string& err) {
    pe.img = &b;
    if (b.size() < 0x200 || b[0] != 'M' || b[1] != 'Z') { err = "not a PE file"; return false; }
    pe.ntOff = rd<uint32_t>(b, 0x3C);
    if (pe.ntOff + 0x108 > b.size() || rd<uint32_t>(b, pe.ntOff) != 0x00004550) { err = "bad NT header"; return false; }
    pe.fileHdrOff = pe.ntOff + 4;
    if (rd<uint16_t>(b, pe.fileHdrOff) != 0x8664) { err = "not x64"; return false; }
    pe.numSections = rd<uint16_t>(b, pe.fileHdrOff + 2);
    pe.sizeOfOpt = rd<uint16_t>(b, pe.fileHdrOff + 16);
    pe.optOff = pe.fileHdrOff + 20;
    if (rd<uint16_t>(b, pe.optOff) != 0x20B) { err = "not PE32+"; return false; }
    pe.sectionAlign = rd<uint32_t>(b, pe.optOff + 32);
    pe.fileAlign = rd<uint32_t>(b, pe.optOff + 36);
    pe.sizeOfHeaders = rd<uint32_t>(b, pe.optOff + 60);
    pe.secTableOff = pe.optOff + pe.sizeOfOpt;
    if (pe.secTableOff + 40ull * pe.numSections > b.size()) { err = "truncated section table"; return false; }
    for (unsigned i = 0; i < pe.numSections; i++) {
        size_t o = pe.secTableOff + 40 * i;
        Section s{};
        std::memcpy(s.name, b.data() + o, 8);
        s.vsize = rd<uint32_t>(b, o + 8);
        s.va = rd<uint32_t>(b, o + 12);
        s.rawsize = rd<uint32_t>(b, o + 16);
        s.rawptr = rd<uint32_t>(b, o + 20);
        s.chars = rd<uint32_t>(b, o + 36);
        s.hdrOff = o;
        if (s.rawsize && (uint64_t)s.rawptr + s.rawsize > b.size()) { err = "section outside file"; return false; }
        pe.secs.push_back(s);
    }
    return true;
}

enum Kind { K_POPCNT, K_CRC32, K_PCMPGTQ, K_PCMPSTR };

struct Site {
    uint32_t rva;
    uint8_t len;
    Kind kind;
    uint32_t prevRva;
};

struct Run { uint32_t start, len, used; };

struct Scan {
    std::vector<Site> sites;
    std::vector<Run> runs;
    std::vector<uint32_t> targets;
    std::vector<uint32_t> funcStarts;
};

bool isCandidate(const ZydisDecodedInstruction& in, Kind& k) {
    if (in.encoding != ZYDIS_INSTRUCTION_ENCODING_LEGACY) return false;
    switch (in.mnemonic) {
    case ZYDIS_MNEMONIC_POPCNT: k = K_POPCNT; return true;
    case ZYDIS_MNEMONIC_CRC32: k = K_CRC32; return true;
    case ZYDIS_MNEMONIC_PCMPGTQ: k = K_PCMPGTQ; return true;
    case ZYDIS_MNEMONIC_PCMPESTRI:
    case ZYDIS_MNEMONIC_PCMPESTRM:
    case ZYDIS_MNEMONIC_PCMPISTRI:
    case ZYDIS_MNEMONIC_PCMPISTRM: k = K_PCMPSTR; return true;
    default: return false;
    }
}

void sweep(const PE& pe, const ZydisDecoder& dec, Scan& sc) {
    const auto& b = *pe.img;

    uint32_t prva = pe.dirRva(3), psz = pe.dirSize(3);
    size_t poff = prva ? pe.off(prva) : SIZE_MAX;
    if (poff != SIZE_MAX) {
        for (uint32_t i = 0; i + 12 <= psz && poff + i + 12 <= b.size(); i += 12) {
            uint32_t beg = rd<uint32_t>(b, poff + i);
            if (beg) sc.funcStarts.push_back(beg);
        }
    }
    std::sort(sc.funcStarts.begin(), sc.funcStarts.end());
    sc.funcStarts.erase(std::unique(sc.funcStarts.begin(), sc.funcStarts.end()), sc.funcStarts.end());
    sc.targets = sc.funcStarts;

    for (const auto& s : pe.secs) {
        if (!(s.chars & 0x20000000)) continue;
        if (std::memcmp(s.name, SECNAME, 8) == 0) continue;
        uint32_t size = std::min(s.vsize ? s.vsize : s.rawsize, s.rawsize);
        const uint8_t* base = b.data() + s.rawptr;
        uint32_t pos = 0;
        auto sync = std::lower_bound(sc.funcStarts.begin(), sc.funcStarts.end(), s.va);
        uint32_t runStart = 0, runLen = 0, prevRva = 0;
        auto flushRun = [&](uint32_t endRva) {
            if (runLen >= 6) {
                bool aligned = (endRva % 16) == 0 ||
                               std::binary_search(sc.funcStarts.begin(), sc.funcStarts.end(), endRva);
                if (aligned) sc.runs.push_back({runStart, runLen, 0});
            }
            runLen = 0;
        };
        while (pos < size) {
            uint32_t rva = s.va + pos;
            while (sync != sc.funcStarts.end() && *sync < rva) ++sync;
            ZydisDecoderContext ctx;
            ZydisDecodedInstruction in;
            if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(&dec, &ctx, base + pos, size - pos, &in))) {
                flushRun(rva);
                pos++;
                prevRva = 0;
                continue;
            }
            if (sync != sc.funcStarts.end() && *sync > rva && *sync < rva + in.length) {
                flushRun(rva);
                pos = *sync - s.va;
                prevRva = 0;
                continue;
            }
            if (in.mnemonic == ZYDIS_MNEMONIC_INT3) {
                if (runLen == 0) runStart = rva;
                runLen++;
            } else {
                flushRun(rva);
                if (in.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE && in.raw.imm[0].is_relative) {
                    int64_t t = (int64_t)rva + in.length + in.raw.imm[0].value.s;
                    if (t >= 0 && t < 0x100000000ll) sc.targets.push_back((uint32_t)t);
                }
                Kind k;
                if (isCandidate(in, k)) sc.sites.push_back({rva, in.length, k, prevRva});
            }
            prevRva = rva;
            pos += in.length;
        }
        flushRun(s.va + pos);
    }
    std::sort(sc.targets.begin(), sc.targets.end());
    sc.targets.erase(std::unique(sc.targets.begin(), sc.targets.end()), sc.targets.end());
}

struct Asm {
    std::vector<uint8_t> buf;
    uint32_t baseRva = 0;
    bool ok = true;
    uint32_t cur() const { return baseRva + (uint32_t)buf.size(); }

    void bytes(const void* p, size_t n) {
        auto* c = (const uint8_t*)p;
        buf.insert(buf.end(), c, c + n);
    }
    void rel32(uint8_t opc, uint32_t target) {
        int32_t d = (int32_t)(target - (cur() + 5));
        buf.push_back(opc);
        bytes(&d, 4);
    }
    void jmp(uint32_t t) { rel32(0xE9, t); }
    void call(uint32_t t) { rel32(0xE8, t); }
    void align(unsigned a, uint8_t fill = 0xCC) {
        while (buf.size() % a) buf.push_back(fill);
    }
    void enc(ZydisEncoderRequest& r) {
        uint8_t tmp[ZYDIS_MAX_INSTRUCTION_LENGTH];
        ZyanUSize len = sizeof tmp;
        if (ZYAN_FAILED(ZydisEncoderEncodeInstructionAbsolute(&r, tmp, &len, cur()))) {
            ok = false;
            return;
        }
        bytes(tmp, len);
    }
};

ZydisEncoderRequest req(ZydisMnemonic m) {
    ZydisEncoderRequest r;
    std::memset(&r, 0, sizeof r);
    r.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    r.mnemonic = m;
    return r;
}
void opR(ZydisEncoderRequest& r, ZydisRegister reg) {
    auto& o = r.operands[r.operand_count++];
    o.type = ZYDIS_OPERAND_TYPE_REGISTER;
    o.reg.value = reg;
}
void opI(ZydisEncoderRequest& r, uint64_t v) {
    auto& o = r.operands[r.operand_count++];
    o.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    o.imm.u = v;
}
void opM(ZydisEncoderRequest& r, ZydisRegister base, ZydisRegister index, uint8_t scale,
         int64_t disp, uint16_t size) {
    auto& o = r.operands[r.operand_count++];
    o.type = ZYDIS_OPERAND_TYPE_MEMORY;
    o.mem.base = base;
    o.mem.index = index;
    o.mem.scale = index == ZYDIS_REGISTER_NONE ? 0 : scale;
    o.mem.displacement = disp;
    o.mem.size = size;
}

void memOp(ZydisEncoderRequest& r, const ZydisDecodedOperand& m, uint32_t insRva,
               uint8_t insLen, int64_t rspAdjust, uint16_t size) {
    int64_t disp = m.mem.disp.value;
    if (m.mem.base == ZYDIS_REGISTER_RIP) disp += (int64_t)insRva + insLen;
    if (m.mem.base == ZYDIS_REGISTER_RSP) disp += rspAdjust;
    opM(r, m.mem.base, m.mem.index, m.mem.scale, disp, size);
}
void op2(Asm &e, ZydisMnemonic m, ZydisRegister a, ZydisRegister b)
{
    ZydisEncoderRequest r = req(m);
    opR(r, a), opR(r, b);
    e.enc(r);
}
void opRI(Asm& e, ZydisMnemonic m, ZydisRegister a, uint64_t imm) {
    auto r = req(m); opR(r, a); opI(r, imm); e.enc(r);
}
void opRRip(Asm& e, ZydisMnemonic m, ZydisRegister a, uint32_t absRva, uint16_t size) {
    auto r = req(m); opR(r, a); opM(r, ZYDIS_REGISTER_RIP, ZYDIS_REGISTER_NONE, 0, absRva, size); e.enc(r);
}
void opRsp(Asm& e, ZydisMnemonic m, ZydisRegister x, int32_t disp, bool store) {
    auto r = req(m);
    if (store) { opM(r, ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_NONE, 0, disp, 16); opR(r, x); }
    else { opR(r, x); opM(r, ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_NONE, 0, disp, 16); }
    e.enc(r);
}
void leaRsp(Asm& e, int32_t d) {
    auto r = req(ZYDIS_MNEMONIC_LEA);
    opR(r, ZYDIS_REGISTER_RSP);
    opM(r, ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_NONE, 0, d, 8);
    e.enc(r);
}

ZydisRegister gpr64(ZydisRegister r) { return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r); }
#define gprIndex(r) ZydisRegisterGetId(gpr64(r))
int xmmIndex(ZydisRegister r) { return (int)r - (int)ZYDIS_REGISTER_XMM0; }
bool isHigh8(ZydisRegister r) {
    return r == ZYDIS_REGISTER_AH || r == ZYDIS_REGISTER_CH || r == ZYDIS_REGISTER_DH || r == ZYDIS_REGISTER_BH;
}

#pragma pack(push, 1)
struct EmuDesc {
    int32_t resume_rel, disp;
    uint8_t op, flags, dst, src, base, index, scale, imm, srcsize, dstsize, pad[2];
};
#pragma pack(pop)
static_assert(sizeof(EmuDesc) == 20, "desc layout");
enum { OP_POPCNT = 1, OP_CRC32 = 2, OP_PCMPESTRI = 3, OP_PCMPESTRM = 4, OP_PCMPISTRI = 5,
       OP_PCMPISTRM = 6, OP_PCMPGTQ = 7 };
enum { DF_MEM = 1, DF_RIP = 2, DF_REXW = 4, DF_HIGH8 = 8 };

struct blobhdr { uint32_t entry, k55, k33, k0f, k01; };

struct Dec {
    ZydisDecodedInstruction in;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
};

bool dis(const ZydisDecoder& dec, const PE& pe, uint32_t rva, Dec& d) {
    size_t o = pe.off(rva);
    if (o == SIZE_MAX) return false;
    const Section* s = pe.secOf(rva);
    size_t avail = s->rawptr + s->rawsize - o;
    return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, pe.img->data() + o, avail, &d.in, d.ops));
}

bool badSegment(const Dec& d) {
    for (int i = 0; i < d.in.operand_count_visible; i++)
        if (d.ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            (d.ops[i].mem.segment == ZYDIS_REGISTER_FS || d.ops[i].mem.segment == ZYDIS_REGISTER_GS))
            return true;
    return false;
}

bool emit_body(Asm& e, const Dec& d, uint32_t rva, const blobhdr& bi,
                   uint32_t blobRva, uint32_t ret_to, bool& slow, bool& fast) {
    const auto& in = d.in;
    const auto& dst = d.ops[0];
    const auto& src = d.ops[1];
    slow = false;
    fast = false;
    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
    bool srcMem = src.type == ZYDIS_OPERAND_TYPE_MEMORY;
    if (!srcMem && src.type != ZYDIS_OPERAND_TYPE_REGISTER) return false;

    if (in.mnemonic == ZYDIS_MNEMONIC_POPCNT && (in.operand_width == 32 || in.operand_width == 64)) {
        ZydisRegister D = dst.reg.value, D64 = gpr64(D);
        {
            auto r = req(ZYDIS_MNEMONIC_MOV);
            opR(r, D);
            if (srcMem) memOp(r, src, rva, in.length, 0, in.operand_width / 8);
            else opR(r, src.reg.value);
            e.enc(r);
        }
        ZydisRegister T = (D64 == ZYDIS_REGISTER_RCX) ? ZYDIS_REGISTER_RDX : ZYDIS_REGISTER_RCX;
        auto K = [&](uint32_t off) { return blobRva + off; };
        { auto r = req(ZYDIS_MNEMONIC_PUSH); opR(r, T); e.enc(r); }
        op2(e, ZYDIS_MNEMONIC_MOV, T, D64);
        opRI(e, ZYDIS_MNEMONIC_SHR, T, 1);
        opRRip(e, ZYDIS_MNEMONIC_AND, T, K(bi.k55), 8);
      op2(e, ZYDIS_MNEMONIC_SUB, D64, T);
        op2(e, ZYDIS_MNEMONIC_MOV, T, D64);
        opRRip(e, ZYDIS_MNEMONIC_AND, D64, K(bi.k33), 8);
        opRI(e, ZYDIS_MNEMONIC_SHR, T, 2);
        opRRip(e, ZYDIS_MNEMONIC_AND, T, K(bi.k33), 8);
        op2(e, ZYDIS_MNEMONIC_ADD, D64, T);
        op2(e, ZYDIS_MNEMONIC_MOV, T, D64);
        opRI(e, ZYDIS_MNEMONIC_SHR, T, 4);
        op2(e, ZYDIS_MNEMONIC_ADD, D64, T);
        opRRip(e, ZYDIS_MNEMONIC_AND, D64, K(bi.k0f), 8);
        opRRip(e, ZYDIS_MNEMONIC_IMUL, D64, K(bi.k01), 8);
        opRI(e, ZYDIS_MNEMONIC_SHR, D64, 56);
        { auto r = req(ZYDIS_MNEMONIC_POP); opR(r, T); e.enc(r); }
        op2(e, ZYDIS_MNEMONIC_TEST, D64, D64);
        fast = true;
        return e.ok;
    }

    if (in.mnemonic == ZYDIS_MNEMONIC_PCMPGTQ) {
        ZydisRegister D = dst.reg.value;
        ZydisRegister S = srcMem ? ZYDIS_REGISTER_NONE : src.reg.value;
        ZydisRegister tmp[2];
        int n = 0;
        for (int i = 0; i < 16 && n < 2; i++) {
            auto x = (ZydisRegister)(ZYDIS_REGISTER_XMM0 + i);
            if (x != D && x != S) tmp[n++] = x;
        }
        ZydisRegister T1 = tmp[0], T2 = tmp[1];
        leaRsp(e, -32);
        opRsp(e, ZYDIS_MNEMONIC_MOVDQU, T1, 0, true);
        opRsp(e, ZYDIS_MNEMONIC_MOVDQU, T2, 16, true);
        {
            auto r = req(srcMem ? ZYDIS_MNEMONIC_MOVDQU : ZYDIS_MNEMONIC_MOVDQA);
            opR(r, T2);
            if (srcMem) memOp(r, src, rva, in.length, 32, 16);
            else opR(r, S);
            e.enc(r);
        }
        op2(e, ZYDIS_MNEMONIC_MOVDQA, T1, T2);
        op2(e, ZYDIS_MNEMONIC_PSUBQ, T1, D);
        op2(e, ZYDIS_MNEMONIC_PXOR, D, T2);
        op2(e, ZYDIS_MNEMONIC_PAND, T2, D);
        op2(e, ZYDIS_MNEMONIC_PANDN, D, T1);
        op2(e, ZYDIS_MNEMONIC_POR, D, T2);
        opRI(e, ZYDIS_MNEMONIC_PSRAD, D, 31);
        { auto r = req(ZYDIS_MNEMONIC_PSHUFD); opR(r, D); opR(r, D); opI(r, 0xF5); e.enc(r); }
        opRsp(e, ZYDIS_MNEMONIC_MOVDQU, T1, 0, false);
        opRsp(e, ZYDIS_MNEMONIC_MOVDQU, T2, 16, false);
        leaRsp(e, 32);
        fast = true;
        return e.ok;
    }

    EmuDesc ds{};
    switch (in.mnemonic) {
    case ZYDIS_MNEMONIC_POPCNT: ds.op = OP_POPCNT; break;
    case ZYDIS_MNEMONIC_CRC32: ds.op = OP_CRC32; break;
    case ZYDIS_MNEMONIC_PCMPESTRI: ds.op = OP_PCMPESTRI; break;
    case ZYDIS_MNEMONIC_PCMPESTRM: ds.op = OP_PCMPESTRM; break;
    case ZYDIS_MNEMONIC_PCMPISTRI: ds.op = OP_PCMPISTRI; break;
    case ZYDIS_MNEMONIC_PCMPISTRM: ds.op = OP_PCMPISTRM; break;
    default: return false;
    }
    bool isStr = ds.op >= OP_PCMPESTRI;
    if (isStr) {
        if (in.operand_count_visible < 3 || d.ops[2].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
        ds.imm = (uint8_t)d.ops[2].imm.value.u;
        ds.dst = (uint8_t)xmmIndex(dst.reg.value);
        if (in.raw.rex.W) ds.flags |= DF_REXW;
        ds.srcsize = 16;
    } else {
        ds.dst = (uint8_t)gprIndex(dst.reg.value);
        ds.dstsize = (uint8_t)(dst.size / 8);
        ds.srcsize = (uint8_t)(src.size / 8);
    }
    ds.base = ds.index = 0xFF;
    if (srcMem) {
        ds.flags |= DF_MEM;
        if (src.mem.base == ZYDIS_REGISTER_RIP) {
            ds.flags |= DF_RIP;
        } else {
            if (src.mem.base != ZYDIS_REGISTER_NONE) ds.base = (uint8_t)gprIndex(src.mem.base);
            if (src.mem.index != ZYDIS_REGISTER_NONE) ds.index = (uint8_t)gprIndex(src.mem.index);
            ds.scale = src.mem.scale ? src.mem.scale : 1;
            int64_t disp = src.mem.disp.value;
            if (disp < INT32_MIN || disp > INT32_MAX) return false;
            ds.disp = (int32_t)disp;
        }
    } else if (isStr) {
        ds.src = (uint8_t)xmmIndex(src.reg.value);
    } else {
        ds.src = (uint8_t)gprIndex(src.reg.value);
        if (isHigh8(src.reg.value)) ds.flags |= DF_HIGH8;
    }
    e.call(blobRva + bi.entry);
    uint32_t descRva = e.cur();
    ds.resume_rel = (int32_t)(ret_to - descRva);
    if (ds.flags & DF_RIP) {
        uint32_t target = rva + in.length + (int32_t)src.mem.disp.value;
        ds.disp = (int32_t)(target - descRva);
    }
    e.bytes(&ds, sizeof ds);
    slow = true;
    return e.ok;
}

bool relocatable(const Dec& d) {
    const auto& in = d.in;
    if (in.mnemonic == ZYDIS_MNEMONIC_INT3 || in.mnemonic == ZYDIS_MNEMONIC_UD2) return false;
    if (in.meta.branch_type == ZYDIS_BRANCH_TYPE_NONE) return true;
    if (in.meta.category != ZYDIS_CATEGORY_COND_BR && in.meta.category != ZYDIS_CATEGORY_UNCOND_BR) return false;
    if (in.mnemonic == ZYDIS_MNEMONIC_JRCXZ || in.mnemonic == ZYDIS_MNEMONIC_JECXZ ||
        in.mnemonic == ZYDIS_MNEMONIC_LOOP || in.mnemonic == ZYDIS_MNEMONIC_LOOPE ||
        in.mnemonic == ZYDIS_MNEMONIC_LOOPNE)
        return false;
    return true;
}

bool relocate(Asm& e, const Dec& d, uint32_t rva, const std::vector<uint8_t>& img, size_t off) {
    if (!(d.in.attributes & ZYDIS_ATTRIB_IS_RELATIVE)) {
        e.bytes(img.data() + off, d.in.length);
        return true;
    }
    ZydisEncoderRequest r;
    if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(&d.in, d.ops, d.in.operand_count_visible, &r)))
        return false;
    for (int i = 0; i < r.operand_count; i++) {
        if (r.operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && r.operands[i].mem.base == ZYDIS_REGISTER_RIP)
            r.operands[i].mem.displacement += (int64_t)rva + d.in.length;
        if (r.operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.in.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE) {
            r.operands[i].imm.s += (int64_t)rva + d.in.length;
            r.branch_type = ZYDIS_BRANCH_TYPE_NONE;
            r.branch_width = ZYDIS_BRANCH_WIDTH_NONE;
        }
    }
    size_t before = e.buf.size();
    e.enc(r);
    if (!e.ok) { e.buf.resize(before); e.ok = true; return false; }
    return true;
}

uint32_t peChecksum(const std::vector<uint8_t>& b, size_t csumOff) {
    uint64_t sum = 0;
    size_t n = b.size();
    for (size_t i = 0; i < n; i += 2) {
        if (i == csumOff || i == csumOff + 2) continue;
        uint16_t w = b[i] | (i + 1 < n ? b[i + 1] << 8 : 0);
        sum += w;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint32_t)(sum + n);
}

void initDecoder(ZydisDecoder& dec) {
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
}

bool hasOurSection(const PE& pe) {
    for (auto& s : pe.secs)
        if (std::memcmp(s.name, SECNAME, 8) == 0) return true;
    return false;
}

void count(const Scan& sc, Stats& st) {
    for (auto& s : sc.sites) {
        switch (s.kind) {
        case K_POPCNT: st.popcnt++; break;
        case K_CRC32: st.crc32++; break;
        case K_PCMPGTQ: st.pcmpgtq++; break;
        case K_PCMPSTR: st.pcmpstr++; break;
        }
    }
}

}

const char* ResultName(Result r) {
    switch (r) {
    case Result::Patched: return "patched";
    case Result::NothingToDo: return "nothing to do";
    case Result::AlreadyPatched: return "already patched";
    case Result::NotX64PE: return "not an x64 PE";
    default: return "error";
    }
}

Result ScanImage(const std::vector<uint8_t>& in, Stats& st, const LogFn& log) {
    PE pe;
    std::string err;
    if (!readPE(in, pe, err)) return Result::NotX64PE;
    if (hasOurSection(pe)) return Result::AlreadyPatched;
    ZydisDecoder dec;
    initDecoder(dec);
    Scan sc;
    sweep(pe, dec, sc);
    count(sc, st);
    (void)log;
    return sc.sites.empty() ? Result::NothingToDo : Result::Patched;
}

Result PatchImage(const std::vector<uint8_t>& in, std::vector<uint8_t>& out, Stats& st, const LogFn& log) {
    PE pe;
    std::string err;
    if (!readPE(in, pe, err)) return Result::NotX64PE;
    if (hasOurSection(pe)) return Result::AlreadyPatched;

    ZydisDecoder dec;
    initDecoder(dec);
    Scan sc;
    sweep(pe, dec, sc);
    count(sc, st);
    if (sc.sites.empty()) return Result::NothingToDo;

    blobhdr bi;
    if (std::memcmp(g_blob, "SSE42EMU", 8) != 0) { log("internal: bad blob"); return Result::Error; }
    std::memcpy(&bi, g_blob + 12, sizeof bi);

    uint32_t endVa = 0, endRaw = 0;
    for (auto& s : pe.secs) {
        endVa = std::max(endVa, s.va + std::max(s.vsize, s.rawsize));
        if (s.rawsize) endRaw = std::max(endRaw, s.rawptr + s.rawsize);
    }
    uint32_t newVa = alignUp(endVa, pe.sectionAlign);
    size_t newHdr = pe.secTableOff + 40ull * pe.numSections;
    uint32_t firstRaw = UINT32_MAX;
    for (auto& s : pe.secs) if (s.rawsize) firstRaw = std::min(firstRaw, s.rawptr);
    if (newHdr + 40 > pe.sizeOfHeaders || newHdr + 40 > firstRaw) {
        log("no room for an additional section header");
        return Result::Error;
    }
    bool clearBound = false;
    for (size_t i = 0; i < 40; i++) {
        if (in[newHdr + i] != 0) {
            if (pe.dirRva(11)) { clearBound = true; break; }
            log("section header area is not empty");
            return Result::Error;
        }
    }

    out = in;
    Asm e;
    e.baseRva = newVa;
    e.bytes(g_blob, sizeof g_blob);
    e.align(16);
    uint32_t blobRva = newVa;

    std::vector<std::pair<uint32_t, uint32_t>> claimed;
    std::map<uint32_t, uint8_t> siteAt;
    for (auto& s : sc.sites) siteAt[s.rva] = s.len;
    auto isTarget = [&](uint32_t rva) { return std::binary_search(sc.targets.begin(), sc.targets.end(), rva); };
    auto writeRva = [&](uint32_t rva, const uint8_t* p, size_t n) {
        size_t o = pe.off(rva);
        std::memcpy(out.data() + o, p, n);
    };
    auto runHit = [&](const Run& r) {
        auto it = std::lower_bound(sc.targets.begin(), sc.targets.end(), r.start);
        return it != sc.targets.end() && *it < r.start + r.len;
    };
    std::vector<bool> runOk(sc.runs.size());
    for (size_t i = 0; i < sc.runs.size(); i++) runOk[i] = !runHit(sc.runs[i]);

    auto grabCave = [&](uint32_t from , uint32_t& slot) -> bool {

        int64_t lo = (int64_t)from - 128, hi = (int64_t)from + 127;
        auto it = std::lower_bound(sc.runs.begin(), sc.runs.end(), (uint32_t)std::max<int64_t>(0, lo - 4096),
                                   [](const Run& r, uint32_t v) { return r.start < v; });
        for (; it != sc.runs.end() && (int64_t)it->start <= hi; ++it) {
            size_t idx = it - sc.runs.begin();
            if (!runOk[idx]) continue;
            Run& r = *it;

            uint32_t s = r.start + 1 + r.used;
            if (s + 5 > r.start + r.len) continue;
            if ((int64_t)s < lo || (int64_t)s > hi) continue;
            r.used += 5;
            slot = s;
            return true;
        }
        return false;
    };

    unsigned nwarn = 20;
    for (auto& site : sc.sites) {
        Dec d;
        if (!dis(dec, pe, site.rva, d) || badSegment(d)) {
            st.skipped++;
            if (nwarn && nwarn--) log(sfmt("  ! cannot decode/handle site at RVA 0x%X", site.rva));
            continue;
        }

        enum { DIRECT, CAVE, STEAL, STEAL_BACK } how = DIRECT;
        uint32_t caveSlot = 0;
        std::vector<std::pair<uint32_t, Dec>> stolen;
        uint32_t stolenLen = 0;
        Dec prevD;
        uint32_t prevLen = 0;
        if (site.len < 5) {
            if (grabCave(site.rva + 2, caveSlot)) {
                how = CAVE;
            } else {
                how = STEAL;
                uint32_t r = site.rva + site.len;
                bool good = true;
                while (site.len + stolenLen < 5) {
                    Dec nd;
                    if (isTarget(r) || siteAt.count(r) || !dis(dec, pe, r, nd) || !relocatable(nd)) {
                        good = false;
                        break;
                    }
                    stolen.push_back({r, nd});
                    stolenLen += nd.in.length;
                    r += nd.in.length;
                }
                if (!good) {
                    stolen.clear();
                    stolenLen = 0;

                    if (site.prevRva && !isTarget(site.rva) && !siteAt.count(site.prevRva) &&
                        dis(dec, pe, site.prevRva, prevD) && relocatable(prevD) &&
                        (prevD.in.meta.branch_type == ZYDIS_BRANCH_TYPE_NONE || prevD.in.meta.category == ZYDIS_CATEGORY_COND_BR) &&
                        site.prevRva + prevD.in.length == site.rva && prevD.in.length + site.len >= 5) {
                        how = STEAL_BACK;
                        prevLen = prevD.in.length;
                    } else {
                        st.skipped++;
                        if (nwarn && nwarn--)
                            log(sfmt("  ! no space to patch %u-byte site at RVA 0x%X", site.len, site.rva));
                        continue;
                    }
                }
            }
        }

        uint32_t tramp = e.cur();
        size_t mark = e.buf.size();
        uint32_t resumeOrig = site.rva + site.len + stolenLen;
        bool generic = false, fast = false;
        bool ok = true;
        if (how == STEAL_BACK)
            ok = relocate(e, prevD, site.prevRva, in, pe.off(site.prevRva));
        size_t emuMark = e.buf.size();
        if (ok) ok = emit_body(e, d, site.rva, bi, blobRva, resumeOrig, generic, fast);

        if (ok && generic && !stolen.empty()) {
            e.buf.resize(emuMark);
            uint32_t probe = e.cur();
            ok = emit_body(e, d, site.rva, bi, blobRva, probe, generic, fast);
            uint32_t resumeHere = e.cur();
            e.buf.resize(emuMark);
            if (ok) ok = emit_body(e, d, site.rva, bi, blobRva, resumeHere, generic, fast);
        }
        if (ok) {
            for (auto& sp : stolen) {
                if (!relocate(e, sp.second, sp.first, in, pe.off(sp.first))) { ok = false; break; }
            }
        }
        if (ok && (!generic || !stolen.empty())) e.jmp(resumeOrig);
        if (!ok) {
            e.buf.resize(mark);
            e.ok = true;
            st.skipped++;
            if (nwarn && nwarn--) log(sfmt("  ! unsupported instruction form at RVA 0x%X", site.rva));
            if (how == CAVE) {
                for (auto& r : sc.runs)
                    if (caveSlot >= r.start && caveSlot < r.start + r.len) { r.used -= 5; break; }
            }
            continue;
        }
        e.align(4);

        uint32_t at = how == STEAL_BACK ? site.prevRva : site.rva;
        uint32_t span = prevLen + site.len + stolenLen;
        std::vector<uint8_t> patch(span, 0xCC);
        if (how == CAVE) {
            patch[0] = 0xEB;
            patch[1] = (uint8_t)(int8_t)((int64_t)caveSlot - (site.rva + 2));
            uint8_t j[5] = {0xE9};
            int32_t rel = (int32_t)(tramp - (caveSlot + 5));
            std::memcpy(j + 1, &rel, 4);
            writeRva(caveSlot, j, 5);
            st.viaCave++;
        } else {
            patch[0] = 0xE9;
            int32_t rel = (int32_t)(tramp - (at + 5));
            std::memcpy(&patch[1], &rel, 4);
            if (how == STEAL || how == STEAL_BACK) st.viaSteal++; else st.direct++;
        }
        writeRva(at, patch.data(), span);
        if (getenv("SSE42_SITES"))
            log(sfmt("SITE %X %X %X %d %X", site.rva, at, span, (int)how, how == CAVE ? caveSlot : 0));
        if (fast) st.inlineFast++; else st.generic++;
    }

    uint32_t vsize = (uint32_t)e.buf.size();
    uint32_t rawSize = alignUp(vsize, pe.fileAlign);
    uint32_t rawPtr = alignUp(endRaw, pe.fileAlign);

    uint32_t certOff = rd<uint32_t>(in, pe.dataDirOff(4)), certSize = rd<uint32_t>(in, pe.dataDirOff(4) + 4);
    std::vector<uint8_t> overlay;
    if (in.size() > endRaw) {
        size_t ovStart = endRaw, ovEnd = in.size();
        if (certSize && certOff >= endRaw && (size_t)certOff + certSize >= ovEnd - 8)
            ovEnd = certOff;
        if (ovEnd > ovStart) {
            overlay.assign(in.begin() + ovStart, in.begin() + ovEnd);
            log(sfmt("  note: keeping %llu bytes of overlay data", (unsigned long long)overlay.size()));
        }
    }
    out.resize(endRaw);
    out.resize(rawPtr, 0);
    out.insert(out.end(), e.buf.begin(), e.buf.end());
    out.resize((size_t)rawPtr + rawSize, 0);
    out.insert(out.end(), overlay.begin(), overlay.end());

    uint8_t hdr[40] = {};
    std::memcpy(hdr, SECNAME, 8);
    std::memcpy(hdr + 8, &vsize, 4);
    std::memcpy(hdr + 12, &newVa, 4);
    std::memcpy(hdr + 16, &rawSize, 4);
    std::memcpy(hdr + 20, &rawPtr, 4);
    uint32_t chars = 0x60000020;
    std::memcpy(hdr + 36, &chars, 4);
    std::memcpy(out.data() + newHdr, hdr, 40);
    wr<uint16_t>(out, pe.fileHdrOff + 2, pe.numSections + 1);
    wr<uint32_t>(out, pe.optOff + 4, rd<uint32_t>(out, pe.optOff + 4) + rawSize);
    wr<uint32_t>(out, pe.optOff + 56, alignUp(newVa + vsize, pe.sectionAlign));
    uint16_t dllch = rd<uint16_t>(out, pe.optOff + 70);
    dllch &= ~0x0080;
    wr<uint16_t>(out, pe.optOff + 70, dllch);
    wr<uint32_t>(out, pe.dataDirOff(4), 0);
    wr<uint32_t>(out, pe.dataDirOff(4) + 4, 0);
    if (clearBound) {
        wr<uint32_t>(out, pe.dataDirOff(11), 0);
        wr<uint32_t>(out, pe.dataDirOff(11) + 4, 0);
    }
    size_t csumOff = pe.optOff + 64;
    wr<uint32_t>(out, csumOff, 0);
    wr<uint32_t>(out, csumOff, peChecksum(out, csumOff));
    return Result::Patched;
}

}
