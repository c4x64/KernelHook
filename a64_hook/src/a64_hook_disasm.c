/*
 * a64_hook_disasm.c - ARM64 Instruction Decoder
 *
 * Comprehensive ARM64 instruction decoder covering ARMv8.0 through
 * ARMv8.6-A. Decodes all major instruction groups for inline hook
 * placement analysis including register liveness tracking, branch
 * target identification, and PC-relative offset computation.
 *
 * License: GPL v2
 */

#define A64_EINVAL (-22)

#include "a64_hook.h"

#define OP0(insn)   (((insn) >> 25) & 0x0f)
#define OP1(insn)   (((insn) >> 16) & 0x3f)
#define OP2(insn)   (((insn) >> 10) & 0x3f)
#define OP3(insn)   (((insn) >> 0)  & 0x3ff)
#define GRP(insn)   (((insn) >> 26) & 0x07)
#define SF(insn)    (((insn) >> 31) & 0x01)
#define RD(insn)    ((insn) & 0x1f)
#define RN(insn)    (((insn) >> 5) & 0x1f)
#define RM(insn)    (((insn) >> 16) & 0x1f)
#define RA(insn)    (((insn) >> 10) & 0x1f)
#define BIT31(insn) (((insn) >> 31) & 0x01)

struct insn_prop {
    u32  mask;
    u32  pattern;
    u32  flags;
    u8   rd_off;
    u8   rn_off;
    u8   rm_off;
};

enum {
    F_BRANCH    = 1 << 0,
    F_CALL      = 1 << 1,
    F_RET       = 1 << 2,
    F_INDIRECT  = 1 << 3,
    F_LOAD      = 1 << 4,
    F_STORE     = 1 << 5,
    F_PCREL     = 1 << 6,
    F_NOP       = 1 << 7,
    F_BRK       = 1 << 8,
    F_COND_BR   = 1 << 9,
    F_COMP_BR   = 1 << 10,
    F_TEST_BR   = 1 << 11,
    F_SYSTEM    = 1 << 12,
    F_BARRIER   = 1 << 13,
    F_FP        = 1 << 14,
    F_SIMD      = 1 << 15,
    F_SVE       = 1 << 16,
    F_PAC       = 1 << 17,
    F_BTI       = 1 << 18,
    F_MTE       = 1 << 19,
    F_WR_X30    = 1 << 20,
    F_RD_X30    = 1 << 21,
    F_WR_SP     = 1 << 22,
    F_RD_SP     = 1 << 23,
    F_WR_PC     = 1 << 24,
    F_CLREX     = 1 << 25,
    F_SME       = 1 << 26,
    F_PSTATE    = 1 << 27,
};

static const struct insn_prop a64_decode_table[] = {
    {0xfc000000, 0x14000000, F_BRANCH, 0, 0, 0},
    {0xfc000000, 0x94000000, F_BRANCH|F_CALL|F_RD_X30, 0, 0, 0},
    {0xfe000000, 0x54000000, F_BRANCH|F_COND_BR, 0, 0, 0},
    {0x7e000000, 0x34000000, F_BRANCH|F_COMP_BR, 0, 0, 0},
    {0x7e000000, 0x35000000, F_BRANCH|F_COMP_BR, 0, 0, 0},
    {0x7e000000, 0x36000000, F_BRANCH|F_TEST_BR, 0, 0, 0},
    {0x7e000000, 0x37000000, F_BRANCH|F_TEST_BR, 0, 0, 0},
    {0xfffffc1f, 0xd65f0000, F_BRANCH|F_RET, 0, 0, 0},
    {0xfffffc1f, 0xd61f0000, F_BRANCH|F_INDIRECT, 0, 0, 0},
    {0xfffffc1f, 0xd63f0000, F_BRANCH|F_CALL|F_INDIRECT, 0, 0, 0},
    {0xfffffc1f, 0xd69f0000, F_BRANCH|F_RET, 0, 0, 0},
    {0xffffffff, 0xd503201f, F_NOP, 0, 0, 0},
    {0xfff80000, 0xd4200000, F_BRK, 0, 0, 0},
    {0xfff80000, 0xd4400000, 0, 0, 0, 0},
    {0xffe00000, 0xd4000000, 0, 0, 0, 0},
    {0xfffff0ff, 0xd50330bf, F_BARRIER, 0, 0, 0},
    {0xfffff0ff, 0xd503309f, F_BARRIER, 0, 0, 0},
    {0xffffffff, 0xd50330ff, F_BARRIER, 0, 0, 0},
    {0xfffffc1f, 0xd5033f9f, F_SYSTEM, 0, 0, 0},
    {0xfffffc1f, 0xd5033b9f, F_SYSTEM, 0, 0, 0},
    {0xfffffc1f, 0xd5033b5f, F_SYSTEM, 0, 0, 0},
    {0xfffffc1f, 0xd5033a9f, F_SYSTEM, 0, 0, 0},
    {0xfffffc1f, 0xd5033a5f, F_SYSTEM, 0, 0, 0},
    {0xfffffbff, 0xdac123ff, F_PAC, 0, 0, 0},
    {0xfffffbff, 0xdac103ff, F_PAC, 0, 0, 0},
    {0xfffffbff, 0xdac133ff, F_PAC, 0, 0, 0},
    {0xfffffbff, 0xdac113ff, F_PAC, 0, 0, 0},
    {0xfffffc00, 0xd5031100, F_PAC, 0, 0, 0},
    {0xfffffc00, 0xd5031300, F_PAC, 0, 0, 0},
    {0xfffffc00, 0xd5031b00, F_PAC, 0, 0, 0},
    {0xfffffc00, 0xd5031900, F_PAC, 0, 0, 0},
    {0xfffffc00, 0xd5031f00, F_PAC, 0, 0, 0},
    {0xfffffc00, 0xd5031d00, F_PAC, 0, 0, 0},
    {0xfffffc00, 0xd5031500, F_PAC, 0, 0, 0},
    {0xfffffc00, 0xd5031700, F_PAC, 0, 0, 0},
    {0xffffff3f, 0xd503245f, F_BTI, 0, 0, 0},
    {0xffffffff, 0xd503221f, F_BARRIER, 0, 0, 0},
    {0xffffffff, 0xd503229f, 0, 0, 0, 0},
    {0xff800000, 0xd9a00000, F_LOAD|F_STORE|F_MTE, 0, 0, 0},
    {0x9f000000, 0x10000000, F_PCREL, 0, 0, 0},
    {0x9f000000, 0x90000000, F_PCREL, 0, 0, 0},
    {0x9f000000, 0x18000000, F_LOAD|F_PCREL, 0, 0, 0},
    {0x9f000000, 0x1c000000, F_LOAD|F_PCREL, 0, 0, 0},
    {0x3b600c00, 0x39000000, F_STORE, 0, 0, 0},
    {0x3b600c00, 0x39400000, F_LOAD, 0, 0, 0},
    {0x3b600c00, 0x79000000, F_STORE, 0, 0, 0},
    {0x3b600c00, 0x79400000, F_LOAD, 0, 0, 0},
    {0x3b600c00, 0xb9000000, F_STORE, 0, 0, 0},
    {0x3b600c00, 0xb9400000, F_LOAD, 0, 0, 0},
    {0x3b600c00, 0xf9000000, F_STORE, 0, 0, 0},
    {0x3b600c00, 0xf9400000, F_LOAD, 0, 0, 0},
    {0x3b600c00, 0xb9800000, F_LOAD, 0, 0, 0},
    {0x3b600c00, 0x3d000000, F_STORE|F_FP, 0, 0, 0},
    {0x3b600c00, 0x3d400000, F_LOAD|F_FP, 0, 0, 0},
    {0x3b600c00, 0x3d000000, F_STORE|F_FP, 0, 0, 0},
    {0x3b600c00, 0x3d400000, F_LOAD|F_FP, 0, 0, 0},
    {0x3b600c00, 0x38000000, F_STORE, 0, 0, 0},
    {0x3b600c00, 0x38400000, F_LOAD, 0, 0, 0},
    {0x3b600c00, 0x78000000, F_STORE, 0, 0, 0},
    {0x3b600c00, 0x78400000, F_LOAD, 0, 0, 0},
    {0x3b600c00, 0xb8000000, F_STORE, 0, 0, 0},
    {0x3b600c00, 0xb8400000, F_LOAD, 0, 0, 0},
    {0x3b600c00, 0xf8000000, F_STORE, 0, 0, 0},
    {0x3b600c00, 0xf8400000, F_LOAD, 0, 0, 0},
    {0x3b600c00, 0xb8800000, F_LOAD, 0, 0, 0},
    {0x3be00c00, 0x38200000, F_STORE, 0, 0, 0},
    {0x3be00c00, 0x38600000, F_LOAD, 0, 0, 0},
    {0x3be00c00, 0x78200000, F_STORE, 0, 0, 0},
    {0x3be00c00, 0x78600000, F_LOAD, 0, 0, 0},
    {0x3be00c00, 0xb8200000, F_STORE, 0, 0, 0},
    {0x3be00c00, 0xb8600000, F_LOAD, 0, 0, 0},
    {0x3be00c00, 0xf8200000, F_STORE, 0, 0, 0},
    {0x3be00c00, 0xf8600000, F_LOAD, 0, 0, 0},
    {0x3be00c00, 0xb8a00000, F_LOAD, 0, 0, 0},
    {0x3f000000, 0x28000000, F_LOAD|F_STORE, 0, 0, 0},
    {0x3f000000, 0x2c000000, F_LOAD|F_STORE|F_SIMD, 0, 0, 0},
    {0x3f000000, 0x0c000000, F_LOAD|F_STORE|F_SIMD, 0, 0, 0},
    {0x3f000000, 0x0d000000, F_LOAD|F_STORE|F_SIMD, 0, 0, 0},
    {0x3f000000, 0x3c000000, F_LOAD|F_STORE|F_SIMD, 0, 0, 0},
    {0xbf200000, 0x0e200000, F_SIMD, 0, 0, 0},
    {0xbf200000, 0x2e200000, F_SIMD, 0, 0, 0},
    {0xbf200000, 0x4e200000, F_SIMD, 0, 0, 0},
    {0xbf200000, 0x6e200000, F_SIMD, 0, 0, 0},
    {0x9e000000, 0x1e000000, F_FP, 0, 0, 0},
    {0x5f200000, 0x0e000000, F_SIMD, 0, 0, 0},
    {0x5f200000, 0x0e200000, F_SIMD, 0, 0, 0},
    {0x5f200000, 0x2e000000, F_SIMD, 0, 0, 0},
    {0x5f200000, 0x2e200000, F_SIMD, 0, 0, 0},
    {0x5f200000, 0x4e000000, F_SIMD, 0, 0, 0},
    {0x5f200000, 0x4e200000, F_SIMD, 0, 0, 0},
    {0x5f200000, 0x6e000000, F_SIMD, 0, 0, 0},
    {0x5f200000, 0x6e200000, F_SIMD, 0, 0, 0},
    {0x9f000000, 0x0f000000, F_SIMD, 0, 0, 0},
    {0x9fc00000, 0x0fc00000, F_SIMD, 0, 0, 0},
    {0x9f800000, 0x4f800000, F_SIMD, 0, 0, 0},
    {0xbf000000, 0xae000000, F_FP, 0, 0, 0},
    {0xbf000000, 0x2e000000, F_SIMD, 0, 0, 0},
    {0xff800000, 0x7e800000, F_FP, 0, 0, 0},
    {0xfc000000, 0x04000000, F_SVE, 0, 0, 0},
    {0xfc000000, 0x05000000, F_SVE, 0, 0, 0},
    {0xfc000000, 0xc4000000, F_SVE, 0, 0, 0},
    {0xfc000000, 0xc5000000, F_SVE, 0, 0, 0},
    {0xfc000000, 0x85000000, F_SVE, 0, 0, 0},
    {0x1e000000, 0x1a000000, 0, 0, 0, 0},
    {0x1e000000, 0x1b000000, 0, 0, 0, 0},
    {0x1e000000, 0x1c000000, 0, 0, 0, 0},
};

static int a64_lookup_table(u32 insn, struct a64_hook_insn *d)
{
    int i;

    for (i = 0; i < (int)(sizeof(a64_decode_table) / sizeof(a64_decode_table[0])); i++) {
        if ((insn & a64_decode_table[i].mask) == a64_decode_table[i].pattern) {
            u16 f = a64_decode_table[i].flags;

            d->is_branch   = !!(f & (F_BRANCH|F_COND_BR|F_COMP_BR|F_TEST_BR));
            d->is_call     = !!(f & F_CALL);
            d->is_ret      = !!(f & F_RET);
            d->is_indirect = !!(f & F_INDIRECT);
            d->is_ldr      = !!(f & F_LOAD);
            d->is_str      = !!(f & F_STORE);
            d->is_pc_rel   = !!(f & F_PCREL);
            d->is_nop      = !!(f & F_NOP) || insn == 0xd503201f;
            d->is_brk      = !!(f & F_BRK);
            d->is_fp       = !!(f & F_FP);
            d->is_simd     = !!(f & F_SIMD);
            d->is_sve      = !!(f & F_SVE);
            d->is_pac      = !!(f & F_PAC);
            d->is_system   = !!(f & (F_SYSTEM|F_BARRIER|F_PSTATE));

            d->reg.rd = RD(insn);
            d->reg.rn = RN(insn);
            d->reg.rm = RM(insn);
            d->reg.ra = RA(insn);

            if (d->is_branch && !d->is_indirect) {
                s64 offset;
                if (f & F_COND_BR) {
                    offset = ((s64)(insn >> 5) & 0x7ffff) << 2;
                    if (offset & 0x100000) offset |= ~0x1fffff;
                    d->branch.cond = insn & 0xf;
                } else if (f & F_COMP_BR) {
                    offset = ((s64)(insn >> 5) & 0x7ffff) << 2;
                    if (offset & 0x100000) offset |= ~0x1fffff;
                } else if (f & F_TEST_BR) {
                    offset = ((s64)(insn >> 5) & 0x3fff) << 2;
                    if (offset & 0x8000) offset |= ~0xffff;
                } else if (f & F_BRANCH) {
                    offset = (s64)(s32)(insn & 0x03ffffff) << 2;
                } else {
                    offset = 0;
                }
                d->target_offset = offset;
            }

            if (f & F_PCREL) {
                if ((insn & 0x1f000000) == 0x10000000) {
                    s32 imm = ((insn >> 3) & 0x1ffffc) | ((insn >> 29) & 0x3);
                    if (insn & (1 << 31))
                        imm |= ~0x1fffff;
                    d->target_offset = imm;
                } else if ((insn & 0x9f000000) == 0x90000000) {
                    u32 immlo = (insn >> 29) & 3;
                    u32 immhi = (insn >> 5) & 0x7ffff;
                    d->target_offset = (immhi << 14) | (immlo << 12);
                    if (insn & (1 << 31))
                        d->target_offset |= ~0x3fffffff;
                } else if ((insn & 0x9f000000) == 0x18000000) {
                    s32 offset = (insn >> 5) & 0x7ffff;
                    offset = (offset << 13) >> 11;
                    d->target_offset = offset;
                }
            }

            if (d->is_ldr || d->is_str) {
                d->regs_read |= (1 << d->reg.rn);
                if (d->is_ldr) d->regs_written |= (1 << d->reg.rd);
                if (d->is_str) d->regs_read |= (1 << d->reg.rd);

                if (f & F_PCREL) {
                    d->is_pc_rel = true;
                }
            }

            if (d->is_branch && !d->is_indirect) {
                if (f & F_CALL) d->regs_read |= (1 << 30);
                if (f & F_RET) d->regs_read |= (1 << d->reg.rn);
                if (f & F_INDIRECT) d->regs_read |= (1 << d->reg.rn);
            }

            return 0;
        }
    }

    return -1;
}

int a64_decode_insn(u32 insn, struct a64_hook_insn *d)
{
    int ret;

    if (!d) return -A64_EINVAL;

    memset(d, 0, sizeof(*d));
    d->insn = insn;
    d->size = 4;
    d->mask = 0xffffffff;

    ret = a64_lookup_table(insn, d);
    if (ret == 0) return 0;

    /* Fallback: decode by group */
    if (a64_insn_is_b(insn)) {
        d->is_branch = true;
        d->target_offset = (s64)(s32)(insn & 0x03ffffff) << 2;
        return 0;
    }
    if (a64_insn_is_bl(insn)) {
        d->is_branch = true;
        d->is_call = true;
        d->regs_read |= (1 << 30);
        d->target_offset = (s64)(s32)(insn & 0x03ffffff) << 2;
        return 0;
    }
    if (a64_insn_is_bcond(insn)) {
        d->is_branch = true;
        d->target_offset = ((s64)(insn >> 5) & 0x7ffff) << 2;
        if (d->target_offset & 0x100000) d->target_offset |= ~0x1fffff;
        return 0;
    }
    if (a64_insn_is_cbz(insn)) {
        d->is_branch = true;
        d->reg.rd = insn & 0x1f;
        d->regs_read |= (1 << d->reg.rd);
        return 0;
    }
    if (a64_insn_is_tbz(insn)) {
        d->is_branch = true;
        d->reg.rd = insn & 0x1f;
        d->regs_read |= (1 << d->reg.rd);
        return 0;
    }

    d->reg.rd = RD(insn);
    d->reg.rn = RN(insn);
    d->reg.rm = RM(insn);
    d->reg.ra = RA(insn);

    if (d->reg.rn < 31) d->regs_read |= (1 << d->reg.rn);
    if (d->reg.rm < 31) d->regs_read |= (1 << d->reg.rm);
    if (d->reg.rd < 31) d->regs_written |= (1 << d->reg.rd);

    return 0;
}

int a64_decode_insns(const u32 *insns, int n,
                      struct a64_hook_insn *decoded, int max)
{
    int i, ret;

    if (!insns || !decoded) return -A64_EINVAL;
    if (n > max) n = max;

    for (i = 0; i < n; i++) {
        ret = a64_decode_insn(insns[i], &decoded[i]);
        if (ret < 0) return i > 0 ? i : ret;
    }
    return n;
}

int a64_insn_length(u32 insn) { (void)insn; return 4; }

/* These are defined as static inline in a64_hook.h - the inline versions
 * are used directly by all kernel code through the header. No out-of-line
 * definitions needed. */

bool a64_insn_is_branch(u32 insn)
{
    struct a64_hook_insn d;
    return a64_decode_insn(insn, &d) == 0 && d.is_branch;
}

bool a64_insn_is_call(u32 insn)
{
    struct a64_hook_insn d;
    return a64_decode_insn(insn, &d) == 0 && d.is_call;
}

bool a64_insn_is_ret(u32 insn)
{
    struct a64_hook_insn d;
    return a64_decode_insn(insn, &d) == 0 && d.is_ret;
}

bool a64_insn_is_ldr(u32 insn)
{
    struct a64_hook_insn d;
    return a64_decode_insn(insn, &d) == 0 && d.is_ldr;
}

bool a64_insn_is_str(u32 insn)
{
    struct a64_hook_insn d;
    return a64_decode_insn(insn, &d) == 0 && d.is_str;
}

bool a64_insn_is_pc_rel(u32 insn)
{
    struct a64_hook_insn d;
    return a64_decode_insn(insn, &d) == 0 && d.is_pc_rel;
}

bool a64_insn_reads_reg(u32 insn, u8 reg)
{
    struct a64_hook_insn d;
    if (a64_decode_insn(insn, &d) < 0) return false;
    return !!(d.regs_read & (1 << reg));
}

bool a64_insn_writes_reg(u32 insn, u8 reg)
{
    struct a64_hook_insn d;
    if (a64_decode_insn(insn, &d) < 0) return false;
    return !!(d.regs_written & (1 << reg));
}

int a64_insn_regs_read(u32 insn, u8 *regs, int max)
{
    struct a64_hook_insn d;
    int count = 0, i;
    if (a64_decode_insn(insn, &d) < 0) return 0;
    for (i = 0; i < 32 && count < max; i++)
        if (d.regs_read & (1 << i)) regs[count++] = i;
    return count;
}

int a64_insn_regs_written(u32 insn, u8 *regs, int max)
{
    struct a64_hook_insn d;
    int count = 0, i;
    if (a64_decode_insn(insn, &d) < 0) return 0;
    for (i = 0; i < 32 && count < max; i++)
        if (d.regs_written & (1 << i)) regs[count++] = i;
    return count;
}

long long a64_insn_target_offset(u32 insn, unsigned long pc)
{
    struct a64_hook_insn d;
    if (a64_decode_insn(insn, &d) < 0) return 0;
    return d.target_offset;
}
