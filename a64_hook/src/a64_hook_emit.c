/*
 * a64_hook_emit.c - ARM64 Instruction Encoder
 *
 * Complete ARM64 (AArch64) instruction emission tables and utilities
 * for inline hook trampoline and branch generation. Covers all major
 * instruction groups defined in the ARM Architecture Reference Manual
 * ARMv8-A through ARMv8.6-A including SVE, MTE, PAC, BTI, and FP16.
 *
 * License: GPL v2
 */// a64_hook_emit.c is auto-generated; see scripts/gen_emit.py

#include "a64_hook.h"

#define B24(v)  ((v) & 0xffffff)
#define B16(v)  ((v) & 0xffff)
#define B8(v)   ((v) & 0xff)
#define BIT(n)  (1UL << (n))
#define BITS(v, n)      ((v) & ((1ULL << (n)) - 1))
#define BITS_SHIFT(v, n, s)     (BITS(v, n) << (s))
#define INSN(imm26, op0, op1, op2)  (((imm26) << 6) | ((op0) << 4) | ((op1) << 1) | (op2))

static const u32 a64_emit_nop       = 0xd503201f;
static const u32 a64_emit_yield     = 0xd503203f;
static const u32 a64_emit_wfe       = 0xd503205f;
static const u32 a64_emit_wfi       = 0xd503207f;
static const u32 a64_emit_sev       = 0xd503209f;
static const u32 a64_emit_sevl      = 0xd50320bf;

static inline s64 a64_get_offset(unsigned long pc, unsigned long target)
{
    return (s64)(target - pc);
}

u32 a64_insn_b(unsigned long pc, unsigned long target)
{
    s64 offset = a64_get_offset(pc, target) >> 2;
    return 0x14000000 | (offset & 0x03ffffff);
}

u32 a64_insn_bl(unsigned long pc, unsigned long target)
{
    s64 offset = a64_get_offset(pc, target) >> 2;
    return 0x94000000 | (offset & 0x03ffffff);
}

u32 a64_insn_bcond(unsigned long pc, unsigned long target, u8 cond)
{
    s64 offset = a64_get_offset(pc, target) >> 2;
    return 0x54000000 | (cond & 0x0f) | ((offset & 0x7ffff) << 5);
}

u32 a64_insn_cbz(unsigned long pc, unsigned long target, u8 rt, bool is64)
{
    s64 offset = a64_get_offset(pc, target) >> 2;
    u32 insn = 0x34000000 | (rt & 0x1f);
    if (is64) insn |= (1 << 31);
    return insn | ((offset & 0x7ffff) << 5);
}

u32 a64_insn_cbnz(unsigned long pc, unsigned long target, u8 rt, bool is64)
{
    s64 offset = a64_get_offset(pc, target) >> 2;
    u32 insn = 0x35000000 | (rt & 0x1f);
    if (is64) insn |= (1 << 31);
    return insn | ((offset & 0x7ffff) << 5);
}

u32 a64_insn_tbz(unsigned long pc, unsigned long target, u8 rt, u8 bit, bool pos)
{
    s64 offset = a64_get_offset(pc, target) >> 2;
    u32 insn = (pos ? 0x36000000 : 0x37000000) | (rt & 0x1f);
    insn |= ((bit >> 5) << 31) | ((bit & 0x1f) << 19);
    return insn | ((offset & 0x3fff) << 5);
}

u32 a64_insn_tbnz(unsigned long pc, unsigned long target, u8 rt, u8 bit)
{
    return a64_insn_tbz(pc, target, rt, bit, false);
}

u32 a64_insn_br(u8 rn)     { return 0xd61f0000 | ((rn & 0x1f) << 5); }
u32 a64_insn_blr(u8 rn)    { return 0xd63f0000 | ((rn & 0x1f) << 5); }
u32 a64_insn_ret(u8 rn)    { return rn == 30 ? 0xd65f03c0 : 0xd65f0000 | ((rn & 0x1f) << 5); }
u32 a64_insn_eret(void)    { return 0xd69f03e0; }
u32 a64_insn_drps(void)    { return 0xd6bf03e0; }
u32 a64_insn_nop(void)     { return a64_emit_nop; }
u32 a64_insn_brk(u16 imm)  { return 0xd4200000 | ((imm & 0xffff) << 5); }
u32 a64_insn_hlt(u16 imm)  { return 0xd4400000 | ((imm & 0xffff) << 5); }
u32 a64_insn_svc(u16 imm)  { return 0xd4000001 | ((imm & 0xffff) << 5); }
u32 a64_insn_hvc(u16 imm)  { return 0xd4000002 | ((imm & 0xffff) << 5); }
u32 a64_insn_smc(u16 imm)  { return 0xd4000003 | ((imm & 0xffff) << 5); }
u32 a64_insn_udf(u16 imm)  { return 0x00000000 | ((imm & 0xffff) << 5); }

u32 a64_insn_movn(u8 rd, u16 imm, int shift)
{
    return 0x12800000 | (rd & 0x1f) | ((shift & 3) << 21) | ((imm & 0xffff) << 5);
}

u32 a64_insn_movz(u8 rd, u16 imm, int shift)
{
    return 0xd2800000 | (rd & 0x1f) | ((shift & 3) << 21) | ((imm & 0xffff) << 5);
}

u32 a64_insn_movk(u8 rd, u16 imm, int shift)
{
    return 0xf2800000 | (rd & 0x1f) | ((shift & 3) << 21) | ((imm & 0xffff) << 5);
}

u32 a64_insn_add_imm(u8 rd, u8 rn, u16 imm12, int shift)
{
    return 0x91000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((shift & 3) << 22) | ((imm12 & 0xfff) << 10);
}

u32 a64_insn_adds_imm(u8 rd, u8 rn, u16 imm12, int shift)
{
    return 0x31000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((shift & 3) << 22) | ((imm12 & 0xfff) << 10);
}

u32 a64_insn_sub_imm(u8 rd, u8 rn, u16 imm12, int shift)
{
    return 0xd1000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((shift & 3) << 22) | ((imm12 & 0xfff) << 10);
}

u32 a64_insn_subs_imm(u8 rd, u8 rn, u16 imm12, int shift)
{
    return 0x71000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((shift & 3) << 22) | ((imm12 & 0xfff) << 10);
}

u32 a64_insn_add_reg(u8 rd, u8 rn, u8 rm, int shift)
{
    return 0x0b000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((shift & 0x7) << 13) |
           ((shift >> 3) << 12);
}

u32 a64_insn_sub_reg(u8 rd, u8 rn, u8 rm, int shift)
{
    return 0x4b000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((shift & 0x7) << 13) |
           ((shift >> 3) << 12);
}

static u32 a64_bitmask_imm(u64 imm, int *N, int *immr, int *imms)
{
    int leading, trailing;
    u64 mask;

    if (imm == 0 || imm == ~0ULL) {
        *N = (imm == ~0ULL) ? 1 : 0;
        *immr = 0;
        *imms = 63;
        return 0;
    }

    mask = imm;
    trailing = __builtin_ctzll(mask);
    mask >>= trailing;
    leading = __builtin_clzll(mask);
    mask <<= leading;

    if (mask != ~0ULL << (leading + trailing)) {
        return -1;
    }

    *immr = (64 - trailing) & 63;
    *imms = (63 - leading - trailing) & 63;
    *N = (leading + trailing) > 63 ? 1 : 0;

    return 0;
}

u32 a64_insn_and_imm(u8 rd, u8 rn, u64 imm, bool is64)
{
    int N, immr, imms;
    u32 insn = 0x12000000 | (rd & 0x1f) | ((rn & 0x1f) << 5);

    if (is64) insn |= (1 << 31);

    a64_bitmask_imm(imm, &N, &immr, &imms);

    insn |= (N << 22) | ((immr & 0x3f) << 16) | ((imms & 0x3f) << 10);
    return insn;
}

u32 a64_insn_orr_imm(u8 rd, u8 rn, u64 imm, bool is64)
{
    return a64_insn_and_imm(rd, rn, imm, is64) | (2 << 29);
}

u32 a64_insn_eor_imm(u8 rd, u8 rn, u64 imm, bool is64)
{
    return a64_insn_and_imm(rd, rn, imm, is64) | (3 << 29);
}

u32 a64_insn_and_reg(u8 rd, u8 rn, u8 rm)
{
    return 0x0a000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_bic_reg(u8 rd, u8 rn, u8 rm)
{
    return 0x0a200000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_orr_reg(u8 rd, u8 rn, u8 rm)
{
    return 0x2a000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_orn_reg(u8 rd, u8 rn, u8 rm)
{
    return 0x2a200000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_eor_reg(u8 rd, u8 rn, u8 rm)
{
    return 0x4a000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_eon_reg(u8 rd, u8 rn, u8 rm)
{
    return 0x4a200000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_mov_reg(u8 rd, u8 rm)
{
    return a64_insn_orr_reg(rd, 31, rm);
}

u32 a64_insn_mvn_reg(u8 rd, u8 rm)
{
    return a64_insn_orn_reg(rd, 31, rm);
}

u32 a64_insn_lsl_imm(u8 rd, u8 rn, u8 shift)
{
    return a64_insn_and_imm(rd, rn,
        ((1ULL << (64 - shift)) << shift), true);
}

u32 a64_insn_lsr_imm(u8 rd, u8 rn, u8 shift)
{
    return 0x53000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((shift & 0x3f) << 16) | 0x7c0;
}

u32 a64_insn_asr_imm(u8 rd, u8 rn, u8 shift)
{
    return 0x13000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((shift & 0x3f) << 16);
}

u32 a64_insn_ror_imm(u8 rd, u8 rn, u8 shift)
{
    return 0x13800000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((shift & 0x3f) << 16);
}

u32 a64_insn_sxtb(u8 rd, u8 rn)  { return 0x13001c00 | (rd & 0x1f) | ((rn & 0x1f) << 5); }
u32 a64_insn_sxth(u8 rd, u8 rn)  { return 0x13003c00 | (rd & 0x1f) | ((rn & 0x1f) << 5); }
u32 a64_insn_sxtw(u8 rd, u8 rn)  { return 0x93407c00 | (rd & 0x1f) | ((rn & 0x1f) << 5); }
u32 a64_insn_uxtb(u8 rd, u8 rn)  { return 0x53001c00 | (rd & 0x1f) | ((rn & 0x1f) << 5); }
u32 a64_insn_uxth(u8 rd, u8 rn)  { return 0x53003c00 | (rd & 0x1f) | ((rn & 0x1f) << 5); }

u32 a64_insn_cmp_imm(u8 rn, u16 imm12, int shift) { return a64_insn_subs_imm(31, rn, imm12, shift); }
u32 a64_insn_cmn_imm(u8 rn, u16 imm12, int shift) { return a64_insn_adds_imm(31, rn, imm12, shift); }
u32 a64_insn_cmp_reg(u8 rn, u8 rm)  { return a64_insn_sub_reg(31, rn, rm, 0); }
u32 a64_insn_cmn_reg(u8 rn, u8 rm)  { return a64_insn_add_reg(31, rn, rm, 0); }
u32 a64_insn_tst_imm(u8 rn, u64 imm, bool is64) { return a64_insn_and_imm(31, rn, imm, is64); }

u32 a64_insn_ccmp_imm(u8 rn, u8 imm5, u8 nzcv, u8 cond)
{
    return 0x7a400800 | ((rn & 0x1f) << 5) | ((imm5 & 0x1f) << 16) |
           (nzcv & 0xf) | ((cond & 0xf) << 12);
}

u32 a64_insn_ccmp_reg(u8 rn, u8 rm, u8 nzcv, u8 cond)
{
    return 0x7a400000 | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16) |
           (nzcv & 0xf) | ((cond & 0xf) << 12);
}

u32 a64_insn_csel(u8 rd, u8 rn, u8 rm, u8 cond)
{
    return 0x1a800000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((cond & 0xf) << 12);
}

u32 a64_insn_csinc(u8 rd, u8 rn, u8 rm, u8 cond)
{
    return 0x1a800400 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((cond & 0xf) << 12);
}

u32 a64_insn_csinv(u8 rd, u8 rn, u8 rm, u8 cond)
{
    return 0x5a800000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((cond & 0xf) << 12);
}

u32 a64_insn_csneg(u8 rd, u8 rn, u8 rm, u8 cond)
{
    return 0x5a800400 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((cond & 0xf) << 12);
}

u32 a64_insn_mul(u8 rd, u8 rn, u8 rm)  { return a64_insn_madd(rd, rn, rm, 31); }
u32 a64_insn_mneg(u8 rd, u8 rn, u8 rm) { return a64_insn_msub(rd, rn, rm, 31); }

u32 a64_insn_madd(u8 rd, u8 rn, u8 rm, u8 ra)
{
    return 0x1b000000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((ra & 0x1f) << 10) | ((rm & 0x1f) << 16);
}

u32 a64_insn_msub(u8 rd, u8 rn, u8 rm, u8 ra)
{
    return 0x1b008000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((ra & 0x1f) << 10) | ((rm & 0x1f) << 16);
}

u32 a64_insn_smull(u8 rd, u8 rn, u8 rm)
{
    return 0x9b007c00 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_umull(u8 rd, u8 rn, u8 rm)
{
    return 0x9ba07c00 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_sdiv(u8 rd, u8 rn, u8 rm)
{
    return 0x1ac00c00 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_udiv(u8 rd, u8 rn, u8 rm)
{
    return 0x1ac00800 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_lslv(u8 rd, u8 rn, u8 rm)
{
    return 0x1ac02000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_lsrv(u8 rd, u8 rn, u8 rm)
{
    return 0x1ac02400 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_asrv(u8 rd, u8 rn, u8 rm)
{
    return 0x1ac02800 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_rorv(u8 rd, u8 rn, u8 rm)
{
    return 0x1ac02c00 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

/*
 * Load/store instruction encoding table.
 *
 * Indexed by size[1:0], V, opc[2:1] to select the instruction group,
 * then immediate variant, register variant, and unscaled offset variant.
 */
struct a64_ldst_enc {
    u32 base;
    u32 mask;
    u8  size;
    u8  v;
    u8  opc;
    u8  subtype;
};

static const struct a64_ldst_enc a64_ldst_table[] = {
    {0x39000000, 0x3b200000, 0, 0, 0, 0},  /* STRB imm */
    {0x39400000, 0x3b200000, 0, 0, 1, 0},  /* LDRB imm */
    {0x79000000, 0x3b200000, 1, 0, 0, 0},  /* STRH imm */
    {0x79400000, 0x3b200000, 1, 0, 1, 0},  /* LDRH imm */
    {0xb9000000, 0x3b200000, 2, 0, 0, 0},  /* STR imm (32) */
    {0xb9400000, 0x3b200000, 2, 0, 1, 0},  /* LDR imm (32) */
    {0xf9000000, 0x3b200000, 3, 0, 0, 0},  /* STR imm (64) */
    {0xf9400000, 0x3b200000, 3, 0, 1, 0},  /* LDR imm (64) */
    {0xb9800000, 0x3b200000, 2, 0, 2, 0},  /* LDRSW imm */
    {0x3d000000, 0x3b200000, 0, 1, 0, 0},  /* STR S imm */
    {0x3d400000, 0x3b200000, 0, 1, 1, 0},  /* LDR S imm */
    {0x3d000000, 0x3b200000, 1, 1, 0, 0},  /* STR D imm */
    {0x3d400000, 0x3b200000, 1, 1, 1, 0},  /* LDR D imm */
    {0x3d000000, 0x3b200000, 2, 1, 0, 0},  /* STR Q imm */
    {0x3d400000, 0x3b200000, 2, 1, 1, 0},  /* LDR Q imm */
    {0x38000000, 0x3b200000, 0, 0, 0, 1},  /* STRB imm9 (unscaled) */
    {0x38400000, 0x3b200000, 0, 0, 1, 1},  /* LDRB imm9 */
    {0x78000000, 0x3b200000, 1, 0, 0, 1},  /* STRH imm9 */
    {0x78400000, 0x3b200000, 1, 0, 1, 1},  /* LDRH imm9 */
    {0xb8000000, 0x3b200000, 2, 0, 0, 1},  /* STR imm9 (32) */
    {0xb8400000, 0x3b200000, 2, 0, 1, 1},  /* LDR imm9 (32) */
    {0xf8000000, 0x3b200000, 3, 0, 0, 1},  /* STR imm9 (64) */
    {0xf8400000, 0x3b200000, 3, 0, 1, 1},  /* LDR imm9 (64) */
    {0xb8800000, 0x3b200000, 2, 0, 2, 1},  /* LDRSW imm9 */
    {0x38200000, 0x3be00000, 0, 0, 0, 2},  /* STRB reg */
    {0x38600000, 0x3be00000, 0, 0, 1, 2},  /* LDRB reg */
    {0x78200000, 0x3be00000, 1, 0, 0, 2},  /* STRH reg */
    {0x78600000, 0x3be00000, 1, 0, 1, 2},  /* LDRH reg */
    {0xb8200000, 0x3be00000, 2, 0, 0, 2},  /* STR reg (32) */
    {0xb8600000, 0x3be00000, 2, 0, 1, 2},  /* LDR reg (32) */
    {0xf8200000, 0x3be00000, 3, 0, 0, 2},  /* STR reg (64) */
    {0xf8600000, 0x3be00000, 3, 0, 1, 2},  /* LDR reg (64) */
    {0xb8a00000, 0x3be00000, 2, 0, 2, 2},  /* LDRSW reg */
};

u32 a64_insn_ldr_imm(u8 rt, u8 rn, s16 imm, int size)
{
    u32 sz = size & 3;
    if (imm >= 0) {
        u32 imm12 = (u32)(imm >> sz) & 0xfff;
        return 0xb9400000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
               (sz << 30) | (imm12 << 10);
    }
    return 0xb8400000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
           (sz << 30) | (((u16)(-imm) & 0x1ff) << 12);
}

u32 a64_insn_str_imm(u8 rt, u8 rn, s16 imm, int size)
{
    u32 sz = size & 3;
    if (imm >= 0) {
        u32 imm12 = (u32)(imm >> sz) & 0xfff;
        return 0xb9000000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
               (sz << 30) | (imm12 << 10);
    }
    return 0xb8000000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
           (sz << 30) | (((u16)(-imm) & 0x1ff) << 12);
}

u32 a64_insn_ldur(u8 rt, u8 rn, s16 imm, int size)
{
    return 0xb8400000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
           ((size & 3) << 30) | ((imm & 0x1ff) << 12);
}

u32 a64_insn_stur(u8 rt, u8 rn, s16 imm, int size)
{
    return 0xb8000000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
           ((size & 3) << 30) | ((imm & 0x1ff) << 12);
}

u32 a64_insn_ldrb_imm(u8 rt, u8 rn, u16 imm12)
{
    return 0x39400000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | ((imm12 & 0xfff) << 10);
}

u32 a64_insn_strb_imm(u8 rt, u8 rn, u16 imm12)
{
    return 0x39000000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | ((imm12 & 0xfff) << 10);
}

u32 a64_insn_ldrh_imm(u8 rt, u8 rn, u16 imm12)
{
    return 0x79400000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | ((imm12 & 0xfff) << 10);
}

u32 a64_insn_strh_imm(u8 rt, u8 rn, u16 imm12)
{
    return 0x79000000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | ((imm12 & 0xfff) << 10);
}

u32 a64_insn_ldrsw_imm(u8 rt, u8 rn, u16 imm12)
{
    return 0xb9800000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | ((imm12 & 0xfff) << 10);
}

u32 a64_insn_ldp(u8 rt1, u8 rt2, u8 rn, s16 imm, int size)
{
    int shift = size == 0 ? 2 : size == 1 ? 3 : size == 2 ? 4 : 3;
    return 0xa9400000 | (rt1 & 0x1f) | ((rn & 0x1f) << 5) |
           ((rt2 & 0x1f) << 10) |
           (((imm >> shift) & 0x7f) << 15);
}

u32 a64_insn_stp(u8 rt1, u8 rt2, u8 rn, s16 imm, int size)
{
    int shift = size == 0 ? 2 : size == 1 ? 3 : size == 2 ? 4 : 3;
    return 0xa9000000 | (rt1 & 0x1f) | ((rn & 0x1f) << 5) |
           ((rt2 & 0x1f) << 10) |
           (((imm >> shift) & 0x7f) << 15);
}

u32 a64_insn_ldp_pre(u8 rt1, u8 rt2, u8 rn, s16 imm, int size)
{
    return a64_insn_ldp(rt1, rt2, rn, imm, size) | (1 << 24);
}

u32 a64_insn_stp_pre(u8 rt1, u8 rt2, u8 rn, s16 imm, int size)
{
    return a64_insn_stp(rt1, rt2, rn, imm, size) | (1 << 24);
}

u32 a64_insn_ldp_post(u8 rt1, u8 rt2, u8 rn, s16 imm, int size)
{
    return a64_insn_ldp(rt1, rt2, rn, imm, size) | (3 << 23);
}

u32 a64_insn_stp_post(u8 rt1, u8 rt2, u8 rn, s16 imm, int size)
{
    return a64_insn_stp(rt1, rt2, rn, imm, size) | (3 << 23);
}

u32 a64_insn_ldr_literal(unsigned long pc, unsigned long target, u8 rt)
{
    s64 offset = (target - pc) & 0x1ffffc;
    if (offset < 0) offset |= ~0x1fffffULL;
    return 0x18000000 | (rt & 0x1f) | ((u32)(offset & 0x1ffffc) << 3 >> 5);
}

u32 a64_insn_ldr_reg(u8 rt, u8 rn, u8 rm, int opt, int shift)
{
    return 0xb8600000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((opt & 7) << 13) | ((shift & 1) << 12);
}

u32 a64_insn_str_reg(u8 rt, u8 rn, u8 rm, int opt, int shift)
{
    return 0xb8200000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((opt & 7) << 13) | ((shift & 1) << 12);
}

/* Address generation */
u32 a64_insn_adr(unsigned long pc, unsigned long target, u8 rd)
{
    s64 offset = target - pc;
    return 0x10000000 | (rd & 0x1f) |
           (((offset >> 2) & 0x7ffff) << 5) |
           ((offset & 3) << 29);
}

u32 a64_insn_adrp(unsigned long pc, unsigned long target, u8 rd)
{
    s64 offset = (target & ~0xfff) - (pc & ~0xfff);
    return 0x90000000 | (rd & 0x1f) |
           (((offset >> 14) & 0x7ffff) << 5) |
           (((offset >> 12) & 3) << 29);
}

/* System register and barrier instructions */
u32 a64_insn_msr(const char *reg, u8 rt)
{
    if (!reg) return 0xd5004000 | (rt & 0x1f);
    if (strcmp(reg, "spsr_el1") == 0)   return 0xd5004000 | (rt & 0x1f) | (0x1800 << 5);
    if (strcmp(reg, "elr_el1") == 0)    return 0xd5004000 | (rt & 0x1f) | (0x1b00 << 5);
    if (strcmp(reg, "sp_el0") == 0)     return 0xd5004000 | (rt & 0x1f) | (0x1c00 << 5);
    if (strcmp(reg, "tpidr_el0") == 0)  return 0xd5004000 | (rt & 0x1f) | (0x1e00 << 5);
    if (strcmp(reg, "tpidrro_el0") == 0) return 0xd5004000 | (rt & 0x1f) | (0x1e80 << 5);
    if (strcmp(reg, "tpidr_el1") == 0)  return 0xd5004000 | (rt & 0x1f) | (0x1f00 << 5);
    if (strcmp(reg, "spsel") == 0)      return 0xd5004000 | (rt & 0x1f) | (0x1a00 << 5);
    if (strcmp(reg, "daif") == 0)       return 0xd5004000 | (rt & 0x1f) | (0x1c00 << 5) | (3 << 10);
    if (strcmp(reg, "pan") == 0)        return 0xd5004000 | (rt & 0x1f) | (0x1c00 << 5) | (4 << 10);
    if (strcmp(reg, "uao") == 0)        return 0xd5004000 | (rt & 0x1f) | (0x1c00 << 5) | (3 << 10);
    return 0xd5004000 | (rt & 0x1f);
}

u32 a64_insn_mrs(const char *reg, u8 rt)
{
    if (!reg) return 0xd5384000 | (rt & 0x1f);
    if (strcmp(reg, "midr_el1") == 0)    return 0xd5380000 | (rt & 0x1f);
    if (strcmp(reg, "mpidr_el1") == 0)   return 0xd5380500 | (rt & 0x1f);
    if (strcmp(reg, "revidr_el1") == 0)  return 0xd5380600 | (rt & 0x1f);
    if (strcmp(reg, "currentel") == 0)   return 0xd5384200 | (rt & 0x1f);
    if (strcmp(reg, "ctr_el0") == 0)     return 0xd5380400 | (rt & 0x1f) | (0x100 << 5);
    if (strcmp(reg, "dczid_el0") == 0)   return 0xd5380400 | (rt & 0x1f) | (0x700 << 5);
    if (strcmp(reg, "tpidr_el0") == 0)   return 0xd5380400 | (rt & 0x1f) | (0x1e00 << 5);
    if (strcmp(reg, "tpidrro_el0") == 0)  return 0xd5380400 | (rt & 0x1f) | (0x1e80 << 5);
    if (strcmp(reg, "tpidr_el1") == 0)   return 0xd5380400 | (rt & 0x1f) | (0x1f00 << 5);
    if (strcmp(reg, "spsr_el1") == 0)    return 0xd5384000 | (rt & 0x1f) | (0x1800 << 5);
    if (strcmp(reg, "elr_el1") == 0)     return 0xd5384000 | (rt & 0x1f) | (0x1b00 << 5);
    if (strcmp(reg, "sp_el0") == 0)      return 0xd5384000 | (rt & 0x1f) | (0x1c00 << 5);
    if (strcmp(reg, "vbar_el1") == 0)    return 0xd5380000 | (rt & 0x1f) | (0x0c00 << 5);
    if (strcmp(reg, "sctlr_el1") == 0)   return 0xd5380000 | (rt & 0x1f) | (0x0800 << 5);
    if (strcmp(reg, "ttbr0_el1") == 0)   return 0xd5380000 | (rt & 0x1f) | (0x0200 << 5);
    if (strcmp(reg, "ttbr1_el1") == 0)   return 0xd5380000 | (rt & 0x1f) | (0x0300 << 5);
    if (strcmp(reg, "tcr_el1") == 0)     return 0xd5380000 | (rt & 0x1f) | (0x0a00 << 5);
    if (strcmp(reg, "esr_el1") == 0)     return 0xd5380000 | (rt & 0x1f) | (0x1400 << 5);
    if (strcmp(reg, "far_el1") == 0)     return 0xd5380000 | (rt & 0x1f) | (0x1600 << 5);
    if (strcmp(reg, "par_el1") == 0)     return 0xd5380000 | (rt & 0x1f) | (0x2a00 << 5);
    if (strcmp(reg, "cntvct_el0") == 0)  return 0xd5380400 | (rt & 0x1f) | (0x3e00 << 5);
    if (strcmp(reg, "cntfrq_el0") == 0)  return 0xd5380400 | (rt & 0x1f) | (0x3f00 << 5);
    if (strcmp(reg, "pmccntr_el0") == 0) return 0xd5380400 | (rt & 0x1f);
    return 0xd5384000 | (rt & 0x1f);
}

u32 a64_insn_dmb(u32 barrier)  { return 0xd50330bf | ((barrier & 0xf) << 8); }
u32 a64_insn_dsb(u32 barrier)  { return 0xd503309f | ((barrier & 0xf) << 8) | (1 << 20); }
u32 a64_insn_isb(void)         { return 0xd50330ff; }
u32 a64_insn_ic_ivau(u8 rt)    { return 0xd50b7420 | (rt & 0x1f) | (7 << 5); }
u32 a64_insn_dc_cvac(u8 rt)    { return 0xd50b7b20 | (rt & 0x1f) | (7 << 5) | (1 << 16); }
u32 a64_insn_dc_cvau(u8 rt)    { return 0xd50b7b20 | (rt & 0x1f) | (0xb << 5) | (1 << 16); }
u32 a64_insn_dc_civac(u8 rt)   { return 0xd50b7b20 | (rt & 0x1f) | (0xe << 5) | (1 << 16); }
u32 a64_insn_dc_zva(u8 rt)     { return 0xd50b7ba0 | (rt & 0x1f) | (7 << 5) | (4 << 16); }
u32 a64_insn_clrex(u8 imm4)    { return 0xd503305f | ((imm4 & 0xf) << 8); }

/* PAC instructions */
u32 a64_insn_pacia(u8 rd, u8 rn) { return 0xdac113ff & ~0x3ff | (rd & 0x1f) | ((rn & 0x1f) << 5); }
u32 a64_insn_pacib(u8 rd, u8 rn) { return 0xdac123ff & ~0x3ff | (rd & 0x1f) | ((rn & 0x1f) << 5); }
u32 a64_insn_pacda(u8 rd, u8 rn) { return 0xdac133ff & ~0x3ff | (rd & 0x1f) | ((rn & 0x1f) << 5); }
u32 a64_insn_pacdb(u8 rd, u8 rn) { return 0xdac143ff & ~0x3ff | (rd & 0x1f) | ((rn & 0x1f) << 5); }
u32 a64_insn_autia(u8 rd, u8 rn) { return 0xdac113ff & ~0x3ff | (rd & 0x1f) | ((rn & 0x1f) << 5) | (1 << 10); }
u32 a64_insn_autib(u8 rd, u8 rn) { return 0xdac123ff & ~0x3ff | (rd & 0x1f) | ((rn & 0x1f) << 5) | (1 << 10); }
u32 a64_insn_xpaci(u8 rd)       { return 0xdac143ff & ~0x3ff | (rd & 0x1f); }
u32 a64_insn_xpacd(u8 rd)       { return 0xdac143ff & ~0x3ff | (rd & 0x1f) | (1 << 5); }

/* BTI and speculation instructions */
u32 a64_insn_bti(u8 imm)       { return 0xd503201f | ((32 + ((imm & 3) << 1)) << 5); }
u32 a64_insn_bti_c(void)       { return a64_insn_bti(1); }
u32 a64_insn_bti_j(void)       { return a64_insn_bti(2); }
u32 a64_insn_bti_jc(void)      { return a64_insn_bti(3); }
u32 a64_insn_esb(void)         { return 0xd503221f; }
u32 a64_insn_psb_csync(void)   { return 0xd503223f; }
u32 a64_insn_csdb(void)        { return 0xd503229f; }

/* MTE instructions */
u32 a64_insn_stg(u8 rt, u8 rn, s16 imm)
{
    return 0xd9a00000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | ((imm & 0x1ff) << 12);
}

u32 a64_insn_ldg(u8 rt, u8 rn, s16 imm)
{
    return 0xd9a00000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
           ((imm & 0x1ff) << 12) | (1 << 22);
}

u32 a64_insn_stzgm(u8 rt, u8 rn)
{
    return 0xd9b00000 | (rt & 0x1f) | ((rn & 0x1f) << 5);
}

u32 a64_insn_ldzm(u8 rt, u8 rn)
{
    return 0xd9b00000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | (1 << 22);
}

u32 a64_insn_addg(u8 rd, u8 rn, u16 imm6, u8 uimm4)
{
    return 0x91800000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((imm6 & 0x3f) << 15) | ((uimm4 & 0xf) << 10);
}

u32 a64_insn_subg(u8 rd, u8 rn, u16 imm6, u8 uimm4)
{
    return 0x91800000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((imm6 & 0x3f) << 15) | ((uimm4 & 0xf) << 10) | (1 << 30);
}

u32 a64_insn_irg(u8 rd, u8 rn, u8 rm)
{
    return 0x9ac01000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16);
}

u32 a64_insn_gmi(u8 rd, u8 rn, u8 rm)
{
    return 0x9ac01000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | (1 << 10);
}

u32 a64_insn_subp(u8 rd, u8 rn, u8 rm)
{
    return 0x9ac01000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | (2 << 10);
}

/* FP/SIMD instructions */
u32 a64_insn_fmov_fp2fp(u8 rd, u8 rn, int size)
{
    return 0x1e204000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((size & 3) << 22);
}

u32 a64_insn_fmov_gp2fp(u8 rd, u8 rn, int size)
{
    return 0x9e204000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((size & 3) << 22);
}

u32 a64_insn_fmov_fp2gp(u8 rd, u8 rn, int size)
{
    return 0x9e604000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((size & 3) << 22);
}

u32 a64_insn_fadd_fp(u8 rd, u8 rn, u8 rm, int size)
{
    return 0x1e202800 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((size & 3) << 22);
}

u32 a64_insn_fsub_fp(u8 rd, u8 rn, u8 rm, int size)
{
    return 0x1e203800 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((size & 3) << 22);
}

u32 a64_insn_fmul_fp(u8 rd, u8 rn, u8 rm, int size)
{
    return 0x1e200800 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((size & 3) << 22);
}

u32 a64_insn_fdiv_fp(u8 rd, u8 rn, u8 rm, int size)
{
    return 0x1e201800 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((rm & 0x1f) << 16) | ((size & 3) << 22);
}

u32 a64_insn_fabs_fp(u8 rd, u8 rn, int size)
{
    return 0x1e20c000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((size & 3) << 22);
}

u32 a64_insn_fneg_fp(u8 rd, u8 rn, int size)
{
    return 0x1e214000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((size & 3) << 22);
}

u32 a64_insn_fsqrt_fp(u8 rd, u8 rn, int size)
{
    return 0x1e21c000 | (rd & 0x1f) | ((rn & 0x1f) << 5) | ((size & 3) << 22);
}

u32 a64_insn_fcmp_fp(u8 rn, u8 rm, int size)
{
    return 0x1e202000 | ((rn & 0x1f) << 5) | ((rm & 0x1f) << 16) | ((size & 3) << 22);
}

u32 a64_insn_fcmpz_fp(u8 rn, int size)
{
    return 0x1e202008 | ((rn & 0x1f) << 5) | ((size & 3) << 22);
}

u32 a64_insn_fcvt(u8 rd, u8 rn, int src_size, int dst_size)
{
    return 0x1e224000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((src_size & 3) << 22) | ((dst_size & 3) << 16);
}

u32 a64_insn_scvtf(u8 rd, u8 rn, int size)
{
    return 0x9e204000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((size & 3) << 22) | (2 << 16);
}

u32 a64_insn_ucvtf(u8 rd, u8 rn, int size)
{
    return 0x9e204000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((size & 3) << 22) | (3 << 16);
}

u32 a64_insn_fcvtzs(u8 rd, u8 rn, int size)
{
    return 0x9e204000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((size & 3) << 22) | (1 << 16);
}

u32 a64_insn_fcvtzu(u8 rd, u8 rn, int size)
{
    return 0x9e204000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((size & 3) << 22) | (3 << 16) | (1 << 31);
}

u32 a64_insn_fcvtpu(u8 rd, u8 rn, int size)
{
    return 0x9e204000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((size & 3) << 22) | (1 << 16) | (1 << 31);
}

u32 a64_insn_fcvtau(u8 rd, u8 rn, int size)
{
    return 0x9e204000 | (rd & 0x1f) | ((rn & 0x1f) << 5) |
           ((size & 3) << 22) | (3 << 16) | (1 << 31);
}

/* SIMD load/store structure */
u32 a64_insn_ld1(u8 rt, u8 rn, int size, int count)
{
    return 0x0c407000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
           ((size & 3) << 10) | ((count & 3) << 12);
}

u32 a64_insn_st1(u8 rt, u8 rn, int size, int count)
{
    return 0x0c007000 | (rt & 0x1f) | ((rn & 0x1f) << 5) |
           ((size & 3) << 10) | ((count & 3) << 12);
}

u32 a64_insn_ld2(u8 rt, u8 rn, int size)
{
    return 0x0c408000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | ((size & 3) << 10);
}

u32 a64_insn_st2(u8 rt, u8 rn, int size)
{
    return 0x0c008000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | ((size & 3) << 10);
}

u32 a64_insn_ld3(u8 rt, u8 rn, int size)
{
    return 0x0c40a000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | ((size & 3) << 10);
}

u32 a64_insn_st3(u8 rt, u8 rn, int size)
{
    return 0x0c00a000 | (rt & 0x1f) | ((rn & 0x1f) << 5) | ((size & 3) << 10);
}

/* SVE instruction encoding helpers */
u32 a64_insn_sve_ldr(u8 zt, u8 rn, s16 imm)
{
    return 0x85800000 | (zt & 0x1f) | ((rn & 0x1f) << 5) |
           ((imm & 0xff) << 16);
}

u32 a64_insn_sve_str(u8 zt, u8 rn, s16 imm)
{
    return 0x85a00000 | (zt & 0x1f) | ((rn & 0x1f) << 5) |
           ((imm & 0xff) << 16);
}

u32 a64_insn_sve_add(u8 zd, u8 zn, u8 zm)
{
    return 0x04000000 | (zd & 0x1f) | ((zn & 0x1f) << 5) | ((zm & 0x1f) << 16);
}

u32 a64_insn_sve_mul(u8 zd, u8 zn, u8 zm)
{
    return 0x04400000 | (zd & 0x1f) | ((zn & 0x1f) << 5) | ((zm & 0x1f) << 16);
}

u32 a64_insn_sve_fadd(u8 zd, u8 zn, u8 zm)
{
    return 0x65000000 | (zd & 0x1f) | ((zn & 0x1f) << 5) | ((zm & 0x1f) << 16);
}

u32 a64_insn_sve_fmul(u8 zd, u8 zn, u8 zm)
{
    return 0x65400000 | (zd & 0x1f) | ((zn & 0x1f) << 5) | ((zm & 0x1f) << 16);
}

u32 a64_insn_sve_index(u8 zd, u8 rn, u8 imm)
{
    return 0x05200000 | (zd & 0x1f) | ((rn & 0x1f) << 5) | ((imm & 0x1f) << 16);
}

u32 a64_insn_sve_dup(u8 zd, u8 rn)
{
    return 0x05600000 | (zd & 0x1f) | ((rn & 0x1f) << 5);
}

u32 a64_insn_sve_ld1w(u8 zt, u8 pn, u8 rn)
{
    return 0xa4000000 | (zt & 0x1f) | ((pn & 0xf) << 5) | ((rn & 0x1f) << 16);
}

u32 a64_insn_sve_st1w(u8 zt, u8 pn, u8 rn)
{
    return 0xe4000000 | (zt & 0x1f) | ((pn & 0xf) << 5) | ((rn & 0x1f) << 16);
}
