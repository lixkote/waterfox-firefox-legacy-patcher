#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#define HIDDEN __attribute__((visibility("hidden")))

struct emu_ctx {
    u8  xmm[16][16];
    u64 r15, r14, r13, r12;
    u64 r11, r10, r9, r8;
    u64 rdi, rsi, rbp, rbx;
    u64 rdx, rcx, rax;
    u64 rflags;
    u64 ret;
};

struct __attribute__((packed)) emu_desc {
    s32 resume_rel;
    s32 disp;
    u8  op;
    u8  flags;
    u8  dst;
    u8  src;
    u8  base;
    u8  index;
    u8  scale;
    u8  imm;
    u8  srcsize;
    u8  dstsize;
    u8  pad[2];
};

enum {
    OP_POPCNT = 1, OP_CRC32 = 2,
    OP_PCMPESTRI = 3, OP_PCMPESTRM = 4, OP_PCMPISTRI = 5, OP_PCMPISTRM = 6,
    OP_PCMPGTQ = 7,
};
enum { DF_MEM = 1, DF_RIP = 2, DF_REXW = 4, DF_HIGH8 = 8 };

#define FL_CF 0x001
#define FL_PF 0x004
#define FL_AF 0x010
#define FL_ZF 0x040
#define FL_SF 0x080
#define FL_OF 0x800
#define FL_ARITH (FL_CF | FL_PF | FL_AF | FL_ZF | FL_SF | FL_OF)

static u64 *gpr_slot(struct emu_ctx *c, unsigned i)
{
    switch (i) {
    case 0: return &c->rax;  case 1: return &c->rcx;
    case 2: return &c->rdx;  case 3: return &c->rbx;
    case 5: return &c->rbp;  case 6: return &c->rsi;
    case 7: return &c->rdi;  case 8: return &c->r8;
    case 9: return &c->r9;   case 10: return &c->r10;
    case 11: return &c->r11; case 12: return &c->r12;
    case 13: return &c->r13; case 14: return &c->r14;
    default: return &c->r15;
    }
}

static u64 get_gpr(struct emu_ctx *c, unsigned i)
{
    if (i == 4)
        return (u64)(&c->ret) + 8;
    return *gpr_slot(c, i);
}

static void *ea(struct emu_ctx *c, const struct emu_desc *d)
{
    u64 a;
    if (d->flags & DF_RIP)
        return (void *)((u64)d + (s64)d->disp);
    a = (u64)(s64)d->disp;
    if (d->base != 0xFF)
        a += get_gpr(c, d->base);
    if (d->index != 0xFF)
        a += get_gpr(c, d->index) * d->scale;
    return (void *)a;
}

static void cpy(void *dst, const void *src, unsigned n)
{
    volatile u8 *o = (volatile u8 *)dst;
    const volatile u8 *s = (const volatile u8 *)src;
    while (n--) *o++ = *s++;
}

static void read_src(struct emu_ctx *c, const struct emu_desc *d, int is_xmm, u8 out[16])
{
    unsigned i;
    for (i = 0; i < 16; i++) out[i] = 0;
    if (d->flags & DF_MEM) {
        cpy(out, ea(c, d), d->srcsize);
    } else if (is_xmm) {
        cpy(out, c->xmm[d->src & 15], 16);
    } else if (d->flags & DF_HIGH8) {
        u64 v = get_gpr(c, d->src);
        out[0] = (u8)(v >> 8);
    } else {
        u64 v = get_gpr(c, d->src);
        cpy(out, &v, d->srcsize);
    }
}

static void fvck_popcnt(struct emu_ctx *c, const struct emu_desc *d)
{
    u8 b[16];
    u64 v, n;
    u64 *dst = gpr_slot(c, d->dst);
    read_src(c, d, 0, b);
    cpy(&v, b, 8);
    v = v - ((v >> 1) & 0x5555555555555555ULL);
    v = (v & 0x3333333333333333ULL) + ((v >> 2) & 0x3333333333333333ULL);
    v = (v + (v >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    n = (v * 0x0101010101010101ULL) >> 56;
    if (d->dstsize == 2)
        *dst = (*dst & ~0xFFFFULL) | n;
    else
        *dst = n;
    c->rflags &= ~(u64)FL_ARITH;
    if (n == 0) c->rflags |= FL_ZF;
}

static u32 crc32c_byte(u32 crc, u8 b)
{
    int k;
    crc ^= b;
    for (k = 0; k < 8; k++)
        crc = (crc >> 1) ^ (0x82F63B78u & (0u - (crc & 1u)));
    return crc;
}

static void crc_op(struct emu_ctx *c, const struct emu_desc *d)
{
    u8 b[16];
    unsigned i;
    u64 *dst = gpr_slot(c, d->dst);
    u32 crc = (u32)*dst;
    read_src(c, d, 0, b);
    for (i = 0; i < d->srcsize; i++)
        crc = crc32c_byte(crc, b[i]);
    *dst = crc;

}

static void gtq(struct emu_ctx *c, const struct emu_desc *d)
{
    u8 b[16];
    s64 x[2], y[2];
    int i;
    read_src(c, d, 1, b);
    cpy(x, c->xmm[d->dst & 15], 16);
    cpy(y, b, 16);
    for (i = 0; i < 2; i++)
        x[i] = (x[i] > y[i]) ? -1 : 0;
    cpy(c->xmm[d->dst & 15], x, 16);
}

static s64 elem(const u8 *v, unsigned i, unsigned fmt)
{
    switch (fmt & 3) {
    case 0: return v[i];
    case 1: return (u16)(v[2 * i] | (v[2 * i + 1] << 8));
    case 2: return (s8)v[i];
    default: return (s16)(u16)(v[2 * i] | (v[2 * i + 1] << 8));
    }
}

static void pcmpstr(struct emu_ctx *c, const struct emu_desc *d)
{
    u8 a[16], b[16];
    unsigned imm = d->imm;
    unsigned fmt = imm & 3;
    unsigned agg = (imm >> 2) & 3;
    unsigned pol = (imm >> 4) & 3;
    unsigned n = (fmt & 1) ? 8 : 16;
    unsigned la, lb, i, j, k;
    u32 res1 = 0, res2, full = (n == 16) ? 0xFFFFu : 0xFFu;
    int explicit_len = (d->op == OP_PCMPESTRI || d->op == OP_PCMPESTRM);
    int want_index = (d->op == OP_PCMPESTRI || d->op == OP_PCMPISTRI);
    u64 fl;

    cpy(a, c->xmm[d->dst & 15], 16);
    read_src(c, d, 1, b);

    if (explicit_len) {
        s64 ra, rd;
        if (d->flags & DF_REXW) { ra = (s64)c->rax; rd = (s64)c->rdx; }
        else { ra = (s32)(u32)c->rax; rd = (s32)(u32)c->rdx; }
        if (ra < 0) ra = -ra;
        if (rd < 0) rd = -rd;
        if (ra < 0 || ra > (s64)n) ra = n;
        if (rd < 0 || rd > (s64)n) rd = n;
        la = (unsigned)ra; lb = (unsigned)rd;
    } else {
        for (la = 0; la < n && elem(a, la, fmt) != 0; la++) ;
        for (lb = 0; lb < n && elem(b, lb, fmt) != 0; lb++) ;
    }

    for (i = 0; i < n; i++) {
        int r = 0;
        switch (agg) {
        case 0:
            for (j = 0; j < n; j++) {
                if (j < la && i < lb && elem(a, j, fmt) == elem(b, i, fmt)) { r = 1; break; }
            }
            break;
        case 1:
            for (j = 0; j + 1 < n; j += 2) {
                if (j < la && i < lb) {
                    s64 bi = elem(b, i, fmt);
                    int ge = bi >= elem(a, j, fmt);
                    int le = (j + 1 < la) ? (bi <= elem(a, j + 1, fmt)) : 0;
                    if (ge && le) { r = 1; break; }
                }
            }
            break;
        case 2:
            if (i >= la && i >= lb) r = 1;
            else if (i >= la || i >= lb) r = 0;
            else r = elem(a, i, fmt) == elem(b, i, fmt);
            break;
        default:
            r = 1;
            for (j = 0, k = i; j < n - i; j++, k++) {
                int br;
                if (j >= la) br = 1;
                else if (k >= lb) br = 0;
                else br = elem(a, j, fmt) == elem(b, k, fmt);
                if (!br) { r = 0; break; }
            }
            break;
        }
        if (r) res1 |= 1u << i;
    }

    switch (pol) {
    case 1: res2 = ~res1 & full; break;
    case 3: res2 = res1 ^ (lb >= 32 ? full : (((1u << lb) - 1) & full)); break;
    default: res2 = res1; break;
    }

    if (want_index) {
        u32 idx;
        if (res2 == 0) idx = n;
        else if (imm & 0x40) { idx = 31 - __builtin_clz(res2); }
        else { idx = __builtin_ctz(res2); }
        c->rcx = idx;
    } else {
        u8 *x0 = c->xmm[0];
        for (i = 0; i < 16; i++) x0[i] = 0;
        if (imm & 0x40) {
            for (i = 0; i < n; i++) {
                if (res2 & (1u << i)) {
                    if (n == 16) x0[i] = 0xFF;
                    else { x0[2 * i] = 0xFF; x0[2 * i + 1] = 0xFF; }
                }
            }
        } else {
            x0[0] = (u8)res2;
            x0[1] = (u8)(res2 >> 8);
        }
    }

    fl = c->rflags & ~(u64)FL_ARITH;
    if (res2) fl |= FL_CF;
    if (lb < n) fl |= FL_ZF;
    if (la < n) fl |= FL_SF;
    if (res2 & 1) fl |= FL_OF;
    c->rflags = fl;
}

HIDDEN void emu_dispatch(struct emu_ctx *c)
{
    const struct emu_desc *d = (const struct emu_desc *)c->ret;
    c->ret = (u64)d + (s64)d->resume_rel;
    switch (d->op) {
    case OP_POPCNT:    fvck_popcnt(c, d); break;
    case OP_CRC32:     crc_op(c, d); break;
    case OP_PCMPGTQ:   gtq(c, d); break;
    case OP_PCMPESTRI:
    case OP_PCMPESTRM:
    case OP_PCMPISTRI:
    case OP_PCMPISTRM: pcmpstr(c, d); break;
    default: __builtin_trap();
    }
}
