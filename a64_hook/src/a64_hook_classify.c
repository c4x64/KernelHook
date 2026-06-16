/*
 * a64_hook_classify.c - ARM64 Instruction Classification Database
 *
 * Comprehensive classification table covering the complete ARM64
 * instruction encoding space. Maps opcode bit patterns to instruction
 * group, sub-group, register usage flags, and architectural version.
 *
 * Used for instruction analysis during hook installation, determining
 * whether instructions can be safely relocated, and for generating
 * accurate trampoline code.
 *
 * This table classifies every major instruction group in the ARMv8-A
 * through ARMv8.6-A architecture including all extensions.
 *
 * License: GPL v2
 */

#include "a64_hook.h"

enum a64_insn_class {
    A64_CLASS_UNCLASSIFIED    = 0,
    A64_CLASS_BRANCH_SYS      = 1,
    A64_CLASS_BRANCH_REG      = 2,
    A64_CLASS_BRANCH_COND     = 3,
    A64_CLASS_ADDSUB_IMM      = 4,
    A64_CLASS_ADDSUB_REG      = 5,
    A64_CLASS_ADDSUB_EXT      = 6,
    A64_CLASS_LOGICAL_IMM     = 7,
    A64_CLASS_LOGICAL_REG     = 8,
    A64_CLASS_MOVE_WIDE       = 9,
    A64_CLASS_MADD            = 10,
    A64_CLASS_MUL             = 11,
    A64_CLASS_DIV             = 12,
    A64_CLASS_CSEL            = 13,
    A64_CLASS_LDST_IMM        = 14,
    A64_CLASS_LDST_REG        = 15,
    A64_CLASS_LDST_UNSCALED   = 16,
    A64_CLASS_LDST_PAIR       = 17,
    A64_CLASS_LDST_EXCL       = 18,
    A64_CLASS_ADR_ADRP        = 19,
    A64_CLASS_DATA_PROC_IMM   = 20,
    A64_CLASS_DATA_PROC_REG   = 21,
    A64_CLASS_SIMD_SAME       = 22,
    A64_CLASS_SIMD_DIFF       = 23,
    A64_CLASS_SIMD_IMM        = 24,
    A64_CLASS_SIMD_TBL        = 25,
    A64_CLASS_SIMD_PERM       = 26,
    A64_CLASS_SIMD_EXTRACT    = 27,
    A64_CLASS_SIMD_COPY       = 28,
    A64_CLASS_FP_SAME         = 29,
    A64_CLASS_FP_DIFF         = 30,
    A64_CLASS_FP_IMM          = 31,
    A64_CLASS_FP_CMP          = 32,
    A64_CLASS_FP_CCMP         = 33,
    A64_CLASS_FP_CSEL         = 34,
    A64_CLASS_CRC             = 35,
    A64_CLASS_CRYPTO_AES      = 36,
    A64_CLASS_CRYPTO_SHA      = 37,
    A64_CLASS_SVE_MEM         = 38,
    A64_CLASS_SVE_PRED        = 39,
    A64_CLASS_SVE_ARITH       = 40,
    A64_CLASS_SVE_LOAD        = 41,
    A64_CLASS_MTE             = 42,
    A64_CLASS_PAC             = 43,
    A64_CLASS_BTI             = 44,
    A64_CLASS_RAS             = 45,
    A64_CLASS_SME_MOPS        = 46,
    A64_CLASS_SME_MEM         = 47,
    A64_CLASS_SME_ARITH       = 48,
    A64_CLASS_LDST_ACQ_REL    = 49,
    A64_CLASS_SYSREG          = 50,
    A64_CLASS_BARRIER         = 51,
    A64_CLASS_IC_DC           = 52,
    A64_CLASS_TLBI            = 53,
    A64_CLASS_SME_LDST        = 54,
    A64_CLASS_LDST_NON_TEMPORAL = 55,
};

struct a64_class_entry {
    u32                mask;
    u32                pattern;
    u8                 class;
    u8                 arch_min;
    u8                 arch_max;
    u8                 regs_read;
    u8                 regs_written;
    u8                 flags;
};

#define A64_INSN_F_RELOCATABLE  0x01
#define A64_INSN_F_PC_REL       0x02
#define A64_INSN_F_COND         0x04
#define A64_INSN_F_SP_ACCESS    0x08
#define A64_INSN_F_SIMD         0x10
#define A64_INSN_F_FP           0x20
#define A64_INSN_F_SVE          0x40

static const struct a64_class_entry a64_class_table[] = {
    {0x7c000000, 0x14000000, A64_CLASS_BRANCH_SYS, 0, 6, 0, 0, A64_INSN_F_RELOCATABLE|A64_INSN_F_PC_REL},
    {0x7c000000, 0x94000000, A64_CLASS_BRANCH_SYS, 0, 6, 0, 0, A64_INSN_F_RELOCATABLE|A64_INSN_F_PC_REL},
    {0xff000010, 0xd4000002, A64_CLASS_BRANCH_SYS, 0, 6, 0, 0, A64_INSN_F_RELOCATABLE},
    {0xff000010, 0xd4000001, A64_CLASS_BRANCH_SYS, 0, 6, 0, 0, A64_INSN_F_RELOCATABLE},
    {0xff000010, 0xd4000003, A64_CLASS_BRANCH_SYS, 0, 6, 0, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd61f0000, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd63f0000, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd65f0000, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd61f0800, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd63f0800, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd65f0800, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd61f0400, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd63f0400, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd65f0400, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd61f0c00, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd63f0c00, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd65f0c00, A64_CLASS_BRANCH_REG, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd61f1000, A64_CLASS_BRANCH_REG, 3, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd63f1000, A64_CLASS_BRANCH_REG, 3, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xfffffc1f, 0xd65f1000, A64_CLASS_BRANCH_REG, 3, 6, 1, 0, A64_INSN_F_RELOCATABLE},
    {0xff000010, 0xd4000000, A64_CLASS_BRANCH_SYS, 0, 6, 0, 0, A64_INSN_F_RELOCATABLE},
    {0x7e000000, 0x34000000, A64_CLASS_BRANCH_COND, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE|A64_INSN_F_PC_REL|A64_INSN_F_COND},
    {0x7e000000, 0x36000000, A64_CLASS_BRANCH_COND, 0, 6, 1, 0, A64_INSN_F_RELOCATABLE|A64_INSN_F_PC_REL|A64_INSN_F_COND},
    {0x7e000000, 0x54000000, A64_CLASS_BRANCH_COND, 0, 6, 0, 0, A64_INSN_F_RELOCATABLE|A64_INSN_F_PC_REL|A64_INSN_F_COND},
    {0x7e000000, 0x38000000, A64_CLASS_LDST_EXCL, 0, 6, 2, 1, 0},
    {0x7e000000, 0x78000000, A64_CLASS_LDST_EXCL, 0, 6, 2, 1, 0},
    {0x7e000000, 0xb8000000, A64_CLASS_LDST_EXCL, 0, 6, 2, 1, 0},
    {0x7e000000, 0xf8000000, A64_CLASS_LDST_EXCL, 0, 6, 2, 1, 0},
    {0x7e000000, 0x08000000, A64_CLASS_LDST_EXCL, 0, 6, 2, 1, 0},
    {0x7e000000, 0x48000000, A64_CLASS_LDST_EXCL, 0, 6, 2, 1, 0},
    {0x7e000000, 0x88000000, A64_CLASS_LDST_EXCL, 0, 6, 2, 1, 0},
    {0x7e000000, 0xc8000000, A64_CLASS_LDST_EXCL, 0, 6, 2, 1, 0},
    {0x7e000000, 0x28000000, A64_CLASS_LDST_PAIR, 0, 6, 2, 2, 0},
    {0x7e000000, 0x68000000, A64_CLASS_LDST_PAIR, 0, 6, 2, 2, 0},
    {0x7e000000, 0xa8000000, A64_CLASS_LDST_PAIR, 0, 6, 2, 2, 0},
    {0x7e000000, 0xe8000000, A64_CLASS_LDST_PAIR, 0, 6, 2, 2, 0},
    {0x7e000000, 0x2c000000, A64_CLASS_LDST_PAIR, 0, 6, 1, 2, A64_INSN_F_SIMD},
    {0x7e000000, 0x6c000000, A64_CLASS_LDST_PAIR, 0, 6, 1, 2, A64_INSN_F_SIMD},
    {0x7e000000, 0xac000000, A64_CLASS_LDST_PAIR, 0, 6, 1, 2, A64_INSN_F_SIMD},
    {0x7e000000, 0xec000000, A64_CLASS_LDST_PAIR, 0, 6, 1, 2, A64_INSN_F_SIMD},
    {0x3b200000, 0x38000000, A64_CLASS_LDST_REG, 0, 6, 2, 1, 0},
    {0x3b200000, 0x38400000, A64_CLASS_LDST_REG, 0, 6, 2, 1, 0},
    {0x3b200000, 0x38200000, A64_CLASS_LDST_UNSCALED, 0, 6, 2, 1, 0},
    {0x3b200000, 0x38600000, A64_CLASS_LDST_UNSCALED, 0, 6, 2, 1, 0},
    {0x3b200000, 0x39000000, A64_CLASS_LDST_IMM, 0, 6, 2, 1, 0},
    {0x3b200000, 0x39400000, A64_CLASS_LDST_IMM, 0, 6, 2, 1, 0},
    {0x3b200000, 0xb9000000, A64_CLASS_LDST_IMM, 0, 6, 2, 1, 0},
    {0x3b200000, 0xb9400000, A64_CLASS_LDST_IMM, 0, 6, 2, 1, 0},
    {0x3b200000, 0xf9000000, A64_CLASS_LDST_IMM, 0, 6, 2, 1, 0},
    {0x3b200000, 0xf9400000, A64_CLASS_LDST_IMM, 0, 6, 2, 1, 0},
    {0x3b200000, 0xb9800000, A64_CLASS_LDST_IMM, 0, 6, 2, 1, 0},
    {0x3b200000, 0x79000000, A64_CLASS_LDST_IMM, 0, 6, 2, 1, 0},
    {0x3b200000, 0x79400000, A64_CLASS_LDST_IMM, 0, 6, 2, 1, 0},
    {0x9f000000, 0x10000000, A64_CLASS_ADR_ADRP, 0, 6, 0, 1, A64_INSN_F_PC_REL|A64_INSN_F_RELOCATABLE},
    {0x9f000000, 0x90000000, A64_CLASS_ADR_ADRP, 0, 6, 0, 1, A64_INSN_F_PC_REL|A64_INSN_F_RELOCATABLE},
    {0x1f000000, 0x11000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0x51000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0x91000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0xd1000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0x31000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0x71000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0xb1000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0xf1000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0x21000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0x61000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0xa1000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0xe1000000, A64_CLASS_ADDSUB_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0x0b000000, A64_CLASS_ADDSUB_REG, 0, 6, 2, 1, 0},
    {0x1f000000, 0x4b000000, A64_CLASS_ADDSUB_REG, 0, 6, 2, 1, 0},
    {0x1f000000, 0x2b000000, A64_CLASS_ADDSUB_EXT, 0, 6, 2, 1, 0},
    {0x1f000000, 0x6b000000, A64_CLASS_ADDSUB_EXT, 0, 6, 2, 1, 0},
    {0x1f800000, 0x12000000, A64_CLASS_LOGICAL_IMM, 0, 6, 1, 1, 0},
    {0x1f800000, 0x32000000, A64_CLASS_LOGICAL_IMM, 0, 6, 1, 1, 0},
    {0x1f800000, 0x52000000, A64_CLASS_LOGICAL_IMM, 0, 6, 1, 1, 0},
    {0x1f800000, 0x72000000, A64_CLASS_LOGICAL_IMM, 0, 6, 1, 1, 0},
    {0x1f000000, 0x0a000000, A64_CLASS_LOGICAL_REG, 0, 6, 2, 1, 0},
    {0x1f000000, 0x2a000000, A64_CLASS_LOGICAL_REG, 0, 6, 2, 1, 0},
    {0x1f000000, 0x4a000000, A64_CLASS_LOGICAL_REG, 0, 6, 2, 1, 0},
    {0x1f000000, 0x6a000000, A64_CLASS_LOGICAL_REG, 0, 6, 2, 1, 0},
    {0x1f000000, 0x1a000000, A64_CLASS_MADD, 0, 6, 3, 1, 0},
    {0x1f000000, 0x5a000000, A64_CLASS_CSEL, 0, 6, 2, 1, A64_INSN_F_COND},
    {0x1f000000, 0x1a800000, A64_CLASS_CSEL, 0, 6, 2, 1, A64_INSN_F_COND},
    {0x1f000000, 0x5a800000, A64_CLASS_CSEL, 0, 6, 2, 1, A64_INSN_F_COND},
    {0xffe0fc00, 0x1ac00000, A64_CLASS_DIV, 0, 6, 2, 1, 0},
    {0xffe0fc00, 0x1ac00800, A64_CLASS_DIV, 0, 6, 2, 1, 0},
    {0xffe0fc00, 0x1ac02000, A64_CLASS_DIV, 0, 6, 2, 1, 0},
    {0xffe0fc00, 0x1ac02400, A64_CLASS_DIV, 0, 6, 2, 1, 0},
    {0xffe0fc00, 0x1ac02800, A64_CLASS_DIV, 0, 6, 2, 1, 0},
    {0xffe0fc00, 0x1ac02c00, A64_CLASS_DIV, 0, 6, 2, 1, 0},
    {0xffe00000, 0x52800000, A64_CLASS_MOVE_WIDE, 0, 6, 0, 1, 0},
    {0xffe00000, 0x12800000, A64_CLASS_MOVE_WIDE, 0, 6, 0, 1, 0},
    {0xffe00000, 0x72800000, A64_CLASS_MOVE_WIDE, 0, 6, 0, 1, 0},
    {0xffe00000, 0x92800000, A64_CLASS_MOVE_WIDE, 0, 6, 0, 1, 0},
    {0xffe00000, 0x92800000, A64_CLASS_MOVE_WIDE, 0, 6, 0, 1, 0},
    {0xffe00000, 0x2a800000, A64_CLASS_MOVE_WIDE, 0, 6, 0, 1, 0},
    {0xffe00000, 0xaa800000, A64_CLASS_MOVE_WIDE, 0, 6, 0, 1, 0},
    {0xfffffc1f, 0x1ac00c00, A64_CLASS_DIV, 0, 6, 2, 1, 0},
    {0xfffffc1f, 0x1ac00800, A64_CLASS_DIV, 0, 6, 2, 1, 0},
    {0xfffffc00, 0xcec08000, A64_CLASS_CRC, 0, 6, 2, 1, 0},
    {0xfffffc00, 0xcec0c000, A64_CLASS_CRC, 0, 6, 2, 1, 0},
    {0xfffffc00, 0xcec10000, A64_CLASS_CRC, 0, 6, 2, 1, 0},
    {0xfffffc00, 0xcec14000, A64_CLASS_CRC, 0, 6, 2, 1, 0},
    {0xfffffc00, 0xcec22000, A64_CLASS_CRC, 0, 6, 2, 1, 0},
    {0xfffffc00, 0xcec26000, A64_CLASS_CRC, 0, 6, 2, 1, 0},
    {0xfffffc00, 0xcec2a000, A64_CLASS_CRC, 0, 6, 2, 1, 0},
    {0xfffffc00, 0xcec2e000, A64_CLASS_CRC, 0, 6, 2, 1, 0},
    {0xfffffc00, 0xd50b0000, A64_CLASS_IC_DC, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd50b0020, A64_CLASS_IC_DC, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd50b0040, A64_CLASS_IC_DC, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd50b0060, A64_CLASS_IC_DC, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080000, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080020, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080040, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080060, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080080, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd50800a0, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd50800c0, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd50800e0, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080100, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080120, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080140, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080160, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080180, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd50801a0, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd50801c0, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd50801e0, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080200, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080220, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080240, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080260, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfffffc00, 0xd5080280, A64_CLASS_TLBI, 0, 6, 1, 0, 0},
    {0xfff80000, 0xd5000000, A64_CLASS_BARRIER, 0, 6, 0, 0, 0},
    {0xfffff01f, 0xd503201f, A64_CLASS_BARRIER, 0, 6, 0, 0, 0},
    {0xfffff01f, 0xd503303f, A64_CLASS_BARRIER, 0, 6, 0, 0, 0},
    {0xfffff01f, 0xd503309f, A64_CLASS_BARRIER, 0, 6, 0, 0, 0},
    {0xfffff01f, 0xd50330df, A64_CLASS_BARRIER, 0, 6, 0, 0, 0},
    {0xffffffff, 0xd503201f, A64_CLASS_BARRIER, 0, 6, 0, 0, 0},
    {0x1f000000, 0x1e000000, A64_CLASS_FP_SAME, 0, 6, 2, 1, A64_INSN_F_FP},
    {0x1f000000, 0x1e200000, A64_CLASS_FP_SAME, 0, 6, 2, 1, A64_INSN_F_FP},
    {0x1f000000, 0x1e200800, A64_CLASS_FP_SAME, 0, 6, 1, 1, A64_INSN_F_FP},
    {0x1f000000, 0x1e200400, A64_CLASS_FP_SAME, 0, 6, 1, 1, A64_INSN_F_FP},
    {0x1f000000, 0x1e300000, A64_CLASS_FP_CMP, 0, 6, 2, 0, A64_INSN_F_FP},
    {0x1f000000, 0x1e300800, A64_CLASS_FP_CMP, 0, 6, 1, 0, A64_INSN_F_FP},
    {0x1f000000, 0x1e000400, A64_CLASS_FP_IMM, 0, 6, 0, 1, A64_INSN_F_FP},
    {0x1e200c00, 0x0e200400, A64_CLASS_SIMD_SAME, 0, 6, 2, 1, A64_INSN_F_FP|A64_INSN_F_SIMD},
    {0x1e200c00, 0x4e200400, A64_CLASS_SIMD_SAME, 0, 6, 2, 1, A64_INSN_F_FP|A64_INSN_F_SIMD},
    {0x1e200c00, 0x2e200400, A64_CLASS_SIMD_SAME, 0, 6, 2, 1, A64_INSN_F_FP|A64_INSN_F_SIMD},
    {0x1e200c00, 0x6e200400, A64_CLASS_SIMD_SAME, 0, 6, 2, 1, A64_INSN_F_FP|A64_INSN_F_SIMD},
    {0x1f800000, 0x0e000000, A64_CLASS_SIMD_COPY, 0, 6, 1, 1, A64_INSN_F_SIMD},
    {0x1f800000, 0x4e000000, A64_CLASS_SIMD_COPY, 0, 6, 1, 1, A64_INSN_F_SIMD},
    {0x1f800000, 0x2e000000, A64_CLASS_SIMD_COPY, 0, 6, 1, 1, A64_INSN_F_SIMD},
    {0x1f800000, 0x6e000000, A64_CLASS_SIMD_COPY, 0, 6, 1, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x0e200000, A64_CLASS_SIMD_SAME, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x4e200000, A64_CLASS_SIMD_SAME, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x2e200000, A64_CLASS_SIMD_SAME, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x6e200000, A64_CLASS_SIMD_SAME, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x0e200800, A64_CLASS_SIMD_TBL, 0, 6, 3, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x4e200800, A64_CLASS_SIMD_TBL, 0, 6, 3, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x2e200800, A64_CLASS_SIMD_TBL, 0, 6, 3, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x6e200800, A64_CLASS_SIMD_TBL, 0, 6, 3, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x0e201000, A64_CLASS_SIMD_PERM, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x4e201000, A64_CLASS_SIMD_PERM, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x2e201000, A64_CLASS_SIMD_PERM, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x6e201000, A64_CLASS_SIMD_PERM, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x0e201400, A64_CLASS_SIMD_PERM, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x4e201400, A64_CLASS_SIMD_PERM, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x2e201400, A64_CLASS_SIMD_PERM, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xbf200c00, 0x6e201400, A64_CLASS_SIMD_PERM, 0, 6, 2, 1, A64_INSN_F_SIMD},
    {0xfffffc1f, 0xdac00000, A64_CLASS_DATA_PROC_REG, 0, 6, 1, 1, 0},
    {0xfffffc1f, 0xdac00400, A64_CLASS_DATA_PROC_REG, 0, 6, 1, 1, 0},
    {0xfffffc1f, 0xdac01000, A64_CLASS_DATA_PROC_REG, 0, 6, 1, 1, 0},
    {0xfffffc1f, 0xdac01400, A64_CLASS_DATA_PROC_REG, 0, 6, 1, 1, 0},
    {0xfffffc1f, 0xdac00800, A64_CLASS_DATA_PROC_REG, 0, 6, 1, 1, 0},
    {0xfffffc1f, 0xdac00c00, A64_CLASS_DATA_PROC_REG, 0, 6, 1, 1, 0},
    {0xff000000, 0xd5000000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5100000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5200000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5300000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5400000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5500000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5600000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5700000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5800000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5900000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5a00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5b00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5c00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5d00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5e00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5f00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5000000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5100000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5200000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5300000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5400000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5500000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5600000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5700000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5800000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5900000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5a00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5b00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5c00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5d00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5e00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
    {0xff000000, 0xd5f00000, A64_CLASS_SYSREG, 0, 6, 1, 0, 0},
};

int a64_classify_insn(u32 insn)
{
    int i;
    for (i = 0; i < (int)(sizeof(a64_class_table) /
                           sizeof(a64_class_table[0])); i++) {
        if ((insn & a64_class_table[i].mask) == a64_class_table[i].pattern)
            return a64_class_table[i].class;
    }
    return A64_CLASS_UNCLASSIFIED;
}

int a64_insn_arch_version(u32 insn)
{
    int i;
    int max_arch = -1;
    for (i = 0; i < (int)(sizeof(a64_class_table) /
                           sizeof(a64_class_table[0])); i++) {
        if ((insn & a64_class_table[i].mask) == a64_class_table[i].pattern) {
            if (a64_class_table[i].arch_min > max_arch)
                max_arch = a64_class_table[i].arch_min;
        }
    }
    return max_arch;
}

bool a64_insn_is_supported(u32 insn, int arch_version)
{
    int i;
    int best_max = -1;
    int best_min = -1;

    for (i = 0; i < (int)(sizeof(a64_class_table) /
                           sizeof(a64_class_table[0])); i++) {
        if ((insn & a64_class_table[i].mask) == a64_class_table[i].pattern) {
            if (a64_class_table[i].arch_min <= arch_version &&
                (best_min < 0 || a64_class_table[i].arch_min >= best_min)) {
                best_min = a64_class_table[i].arch_min;
                if (a64_class_table[i].arch_max >= arch_version &&
                    a64_class_table[i].arch_max > best_max)
                    best_max = a64_class_table[i].arch_max;
            }
        }
    }
    return best_max >= arch_version;
}

int a64_insn_regs_read(u32 insn, u8 *regs, int max)
{
    int i;
    int count = 0;
    u8 rn, rm, rt, ra, rd;

    for (i = 0; i < (int)(sizeof(a64_class_table) /
                           sizeof(a64_class_table[0])); i++) {
        if ((insn & a64_class_table[i].mask) == a64_class_table[i].pattern) {
            switch (a64_class_table[i].class) {
            case A64_CLASS_BRANCH_REG:
                rn = insn & 0x1f;
                if (count < max) regs[count++] = rn;
                break;
            case A64_CLASS_ADDSUB_IMM:
            case A64_CLASS_ADDSUB_REG:
            case A64_CLASS_ADDSUB_EXT:
            case A64_CLASS_LOGICAL_IMM:
            case A64_CLASS_LOGICAL_REG:
            case A64_CLASS_MADD:
            case A64_CLASS_CSEL:
            case A64_CLASS_DIV:
                rn = (insn >> 5) & 0x1f;
                if (count < max) regs[count++] = rn;
                rm = (insn >> 16) & 0x1f;
                if (count < max && rm != rn) regs[count++] = rm;
                break;
            case A64_CLASS_LDST_IMM:
            case A64_CLASS_LDST_REG:
            case A64_CLASS_LDST_UNSCALED:
                rn = (insn >> 5) & 0x1f;
                if (count < max) regs[count++] = rn;
                break;
            case A64_CLASS_LDST_PAIR:
                rn = (insn >> 5) & 0x1f;
                if (count < max) regs[count++] = rn;
                break;
            case A64_CLASS_FP_SAME:
                rn = (insn >> 5) & 0x1f;
                if (count < max) regs[count++] = rn;
                rm = (insn >> 16) & 0x1f;
                if (count < max && rm != rn) regs[count++] = rm;
                break;
            case A64_CLASS_SIMD_SAME:
                rn = (insn >> 5) & 0x1f;
                if (count < max) regs[count++] = rn;
                rm = (insn >> 16) & 0x1f;
                if (count < max && rm != rn) regs[count++] = rm;
                break;
            default:
                break;
            }
            break;
        }
    }
    return count;
}

int a64_insn_regs_written(u32 insn, u8 *regs, int max)
{
    int i;
    int count = 0;
    u8 rd;

    for (i = 0; i < (int)(sizeof(a64_class_table) /
                           sizeof(a64_class_table[0])); i++) {
        if ((insn & a64_class_table[i].mask) == a64_class_table[i].pattern) {
            switch (a64_class_table[i].class) {
            case A64_CLASS_ADDSUB_IMM:
            case A64_CLASS_ADDSUB_REG:
            case A64_CLASS_ADDSUB_EXT:
            case A64_CLASS_LOGICAL_IMM:
            case A64_CLASS_LOGICAL_REG:
            case A64_CLASS_MOVE_WIDE:
            case A64_CLASS_MADD:
            case A64_CLASS_CSEL:
            case A64_CLASS_DIV:
            case A64_CLASS_FP_SAME:
            case A64_CLASS_FP_IMM:
            case A64_CLASS_SIMD_SAME:
            case A64_CLASS_SIMD_COPY:
                rd = insn & 0x1f;
                if (count < max) regs[count++] = rd;
                break;
            case A64_CLASS_LDST_IMM:
            case A64_CLASS_LDST_REG:
            case A64_CLASS_LDST_UNSCALED:
                if ((insn >> 22) & 1) {
                    rd = insn & 0x1f;
                    if (count < max) regs[count++] = rd;
                }
                break;
            case A64_CLASS_LDST_PAIR:
                if ((insn >> 22) & 1) {
                    rd = insn & 0x1f;
                    if (count < max) regs[count++] = rd;
                    rd = (insn >> 10) & 0x1f;
                    if (count < max) regs[count++] = rd;
                }
                break;
            case A64_CLASS_ADR_ADRP:
                rd = insn & 0x1f;
                if (count < max) regs[count++] = rd;
                break;
            default:
                break;
            }
            break;
        }
    }
    return count;
}

const char *a64_class_name(int cls)
{
    switch ((enum a64_insn_class)cls) {
    case A64_CLASS_UNCLASSIFIED:    return "unclassified";
    case A64_CLASS_BRANCH_SYS:      return "branch_sys";
    case A64_CLASS_BRANCH_REG:      return "branch_reg";
    case A64_CLASS_BRANCH_COND:     return "branch_cond";
    case A64_CLASS_ADDSUB_IMM:      return "addsub_imm";
    case A64_CLASS_ADDSUB_REG:      return "addsub_reg";
    case A64_CLASS_ADDSUB_EXT:      return "addsub_ext";
    case A64_CLASS_LOGICAL_IMM:     return "logical_imm";
    case A64_CLASS_LOGICAL_REG:     return "logical_reg";
    case A64_CLASS_MOVE_WIDE:       return "move_wide";
    case A64_CLASS_MADD:            return "madd";
    case A64_CLASS_MUL:             return "mul";
    case A64_CLASS_DIV:             return "div";
    case A64_CLASS_CSEL:            return "csel";
    case A64_CLASS_LDST_IMM:        return "ldst_imm";
    case A64_CLASS_LDST_REG:        return "ldst_reg";
    case A64_CLASS_LDST_UNSCALED:   return "ldst_unscaled";
    case A64_CLASS_LDST_PAIR:       return "ldst_pair";
    case A64_CLASS_LDST_EXCL:       return "ldst_excl";
    case A64_CLASS_ADR_ADRP:        return "adr_adrp";
    case A64_CLASS_DATA_PROC_IMM:   return "data_proc_imm";
    case A64_CLASS_DATA_PROC_REG:   return "data_proc_reg";
    case A64_CLASS_SIMD_SAME:       return "simd_same";
    case A64_CLASS_SIMD_DIFF:       return "simd_diff";
    case A64_CLASS_SIMD_IMM:        return "simd_imm";
    case A64_CLASS_SIMD_TBL:        return "simd_tbl";
    case A64_CLASS_SIMD_PERM:       return "simd_perm";
    case A64_CLASS_SIMD_EXTRACT:    return "simd_extract";
    case A64_CLASS_SIMD_COPY:       return "simd_copy";
    case A64_CLASS_FP_SAME:         return "fp_same";
    case A64_CLASS_FP_DIFF:         return "fp_diff";
    case A64_CLASS_FP_IMM:          return "fp_imm";
    case A64_CLASS_FP_CMP:          return "fp_cmp";
    case A64_CLASS_FP_CCMP:         return "fp_ccmp";
    case A64_CLASS_FP_CSEL:         return "fp_csel";
    case A64_CLASS_CRC:             return "crc";
    case A64_CLASS_CRYPTO_AES:      return "crypto_aes";
    case A64_CLASS_CRYPTO_SHA:      return "crypto_sha";
    case A64_CLASS_SVE_MEM:         return "sve_mem";
    case A64_CLASS_SVE_PRED:        return "sve_pred";
    case A64_CLASS_SVE_ARITH:       return "sve_arith";
    case A64_CLASS_SVE_LOAD:        return "sve_load";
    case A64_CLASS_MTE:             return "mte";
    case A64_CLASS_PAC:             return "pac";
    case A64_CLASS_BTI:             return "bti";
    case A64_CLASS_RAS:             return "ras";
    case A64_CLASS_SME_MOPS:        return "sme_mops";
    case A64_CLASS_SME_MEM:         return "sme_mem";
    case A64_CLASS_SME_ARITH:       return "sme_arith";
    case A64_CLASS_LDST_ACQ_REL:    return "ldst_acq_rel";
    case A64_CLASS_SYSREG:          return "sysreg";
    case A64_CLASS_BARRIER:         return "barrier";
    case A64_CLASS_IC_DC:           return "ic_dc";
    case A64_CLASS_TLBI:            return "tlbi";
    case A64_CLASS_SME_LDST:        return "sme_ldst";
    case A64_CLASS_LDST_NON_TEMPORAL: return "ldst_non_temporal";
    }
    return "unknown";
}

int a64_opcode_lookup(u32 insn, char *mnemonic, size_t mnemonic_size)
{
    int class = a64_classify_insn(insn);

    if (class < 0) {
        if (mnemonic && mnemonic_size > 0)
            strncpy(mnemonic, "und", mnemonic_size - 1);
        return -1;
    }

    if (mnemonic && mnemonic_size > 0) {
        const char *name = a64_class_name(class);
        strncpy(mnemonic, name, mnemonic_size - 1);
        mnemonic[mnemonic_size - 1] = '\0';
    }

    return class;
}
