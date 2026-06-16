/*
 * a64_hook_insndb.c - ARM64 Instruction Encoding Database
 *
 * Comprehensive instruction encoding reference for all defined
 * ARM64 instruction classes through ARMv8.6-A. Provides opcode
 * maps, immediate encoding, and register field descriptions.
 *
 * Used by the hook engine for safe instruction patching and
 * trampoline generation.
 *
 * License: GPL v2
 */

#include "a64_hook.h"

struct a64_opcode_entry {
    u32         mask;
    u32         pattern;
    const char  *mnemonic;
    u8          group;
    u8          form;
    u8          arch_min;
    u8          arch_max;
};

enum {
    A64_ARCH_V8A  = 0,
    A64_ARCH_V81A = 1,
    A64_ARCH_V82A = 2,
    A64_ARCH_V83A = 3,
    A64_ARCH_V84A = 4,
    A64_ARCH_V85A = 5,
    A64_ARCH_V86A = 6,
};

enum {
    A64_FORM_NONE   = 0,
    A64_FORM_IMM    = 1,
    A64_FORM_REG    = 2,
    A64_FORM_LS     = 3,
    A64_FORM_LIT    = 4,
    A64_FORM_COND   = 5,
    A64_FORM_SYS    = 6,
};

static const struct a64_opcode_entry a64_opcode_db[] = {
    /* Branch instructions */
    {0xfc000000, 0x14000000, "b",     0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xfc000000, 0x94000000, "bl",    0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xfffffc1f, 0xd61f0000, "br",    0, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xfffffc1f, 0xd63f0000, "blr",   0, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xfffffc1f, 0xd65f0000, "ret",   0, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xfffffc1f, 0xd65f03c0, "ret",   0, A64_FORM_NONE, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xfffffc1f, 0xd69f0000, "eret",  0, A64_FORM_NONE, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xfffffc1f, 0xd6bf0000, "drps",  0, A64_FORM_NONE, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Conditional branch */
    {0xfe000000, 0x54000000, "b.cond",0, A64_FORM_COND, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Compare and branch */
    {0x7e000000, 0x34000000, "cbz",   0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7e000000, 0x35000000, "cbnz",  0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Test and branch */
    {0x7e000000, 0x36000000, "tbz",   0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7e000000, 0x37000000, "tbnz",  0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},

    /* BTI (from ARMv8.5) */
    {0xffffff3f, 0xd503245f, "bti",   0, A64_FORM_IMM, A64_ARCH_V85A, A64_ARCH_V86A},

    /* Exception generation */
    {0xffe00000, 0xd4000001, "svc",   0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffe00000, 0xd4000002, "hvc",   0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffe00000, 0xd4000003, "smc",   0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xfff80000, 0xd4200000, "brk",   0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xfff80000, 0xd4400000, "hlt",   0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},

    /* System instructions */
    {0xfffff0ff, 0xd50330bf, "dmb",   0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xfffff0ff, 0xd503309f, "dsb",   0, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffffffff, 0xd50330ff, "isb",   0, A64_FORM_NONE, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffffffff, 0xd503201f, "nop",   0, A64_FORM_NONE, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffffffff, 0xd503203f, "yield", 0, A64_FORM_NONE, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffffffff, 0xd503205f, "wfe",   0, A64_FORM_NONE, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffffffff, 0xd503207f, "wfi",   0, A64_FORM_NONE, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffffffff, 0xd503209f, "sev",   0, A64_FORM_NONE, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffffffff, 0xd50320bf, "sevl",  0, A64_FORM_NONE, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffffffff, 0xd503221f, "esb",   0, A64_FORM_NONE, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xffffffff, 0xd503223f, "psb",   0, A64_FORM_NONE, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xffffffff, 0xd503225f, "tsb",   0, A64_FORM_NONE, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xffffffff, 0xd503229f, "csdb",  0, A64_FORM_NONE, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xffffffff, 0xd503233f, "ssbb",  0, A64_FORM_NONE, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xffffffff, 0xd503235f, "pssbb", 0, A64_FORM_NONE, A64_ARCH_V85A, A64_ARCH_V86A},

    /* SVE predicate instructions */
    {0xfc000000, 0x04000000, "sve",   1, A64_FORM_NONE, A64_ARCH_V82A, A64_ARCH_V86A},
    {0xfc000000, 0x05000000, "sve",   1, A64_FORM_NONE, A64_ARCH_V82A, A64_ARCH_V86A},
    {0xfc000000, 0xc4000000, "sve",   1, A64_FORM_NONE, A64_ARCH_V82A, A64_ARCH_V86A},
    {0xfc000000, 0xc5000000, "sve",   1, A64_FORM_NONE, A64_ARCH_V82A, A64_ARCH_V86A},
    {0xfc000000, 0x85000000, "sve",   1, A64_FORM_NONE, A64_ARCH_V82A, A64_ARCH_V86A},

    /* Data processing - immediate */
    {0xff800000, 0x11000000, "add",   2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xff800000, 0x91000000, "add",   2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xff800000, 0x31000000, "adds",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xff800000, 0xb1000000, "adds",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xff800000, 0x51000000, "sub",   2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xff800000, 0xd1000000, "sub",   2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xff800000, 0x71000000, "subs",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xff800000, 0xf1000000, "subs",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Move wide immediate */
    {0x1f800000, 0x12800000, "movn",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x1f800000, 0x52800000, "movz",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x1f800000, 0x72800000, "movk",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Bitfield and extract */
    {0x7f800000, 0x13000000, "sbfm",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f800000, 0x53000000, "ubfm",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f800000, 0x13800000, "bfm",   2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f800000, 0x93400000, "sxtw",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f800000, 0x93407c00, "sxtw",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Logical immediate */
    {0x1f800000, 0x12000000, "and",   2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x1f800000, 0x32000000, "ands",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x1f800000, 0x12800000, "bic",   2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x1f800000, 0x52800000, "orr",   2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x1f800000, 0x72800000, "eor",   2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},

    /* ADR / ADRP */
    {0x1f000000, 0x10000000, "adr",   2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9f000000, 0x90000000, "adrp",  2, A64_FORM_IMM, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Data processing - register */
    {0x7f200000, 0x0b000000, "add",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x8b000000, "add",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x4b000000, "sub",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0xcb000000, "sub",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x2b000000, "adds",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0xab000000, "adds",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x6b000000, "subs",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0xeb000000, "subs",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Logical register */
    {0x7f200000, 0x0a000000, "and",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x8a000000, "and",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x2a000000, "orr",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0xaa000000, "orr",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x4a000000, "eor",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0xca000000, "eor",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x6a000000, "ands",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0xea000000, "ands",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x0a200000, "bic",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x8a200000, "bic",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x2a200000, "orn",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0xaa200000, "orn",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0x4a200000, "eon",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7f200000, 0xca200000, "eon",   3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Multiply */
    {0xff000000, 0x1b000000, "madd",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xff000000, 0x9b000000, "madd",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xff000000, 0x1b008000, "msub",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xff000000, 0x9b008000, "msub",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffe0f000, 0x1ac00800, "udiv",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffe0f000, 0x9ac00800, "udiv",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffe0f000, 0x1ac00c00, "sdiv",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffe0f000, 0x9ac00c00, "sdiv",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Conditional select */
    {0x7fe00c00, 0x1a800000, "csel",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7fe00c00, 0x9a800000, "csel",  3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7fe00c00, 0x1a800400, "csinc", 3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7fe00c00, 0x9a800400, "csinc", 3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7fe00c00, 0x5a800000, "csinv", 3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7fe00c00, 0xda800000, "csinv", 3, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Load register (immediate, unsigned offset) */
    {0xffc00000, 0x39400000, "ldrb",  4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0x79400000, "ldrh",  4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0xb9400000, "ldr",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0xf9400000, "ldr",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0xb9800000, "ldrsw", 4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0x3d400000, "ldr",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0x5d400000, "ldr",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0x3d400000, "ldr",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Store register (immediate, unsigned offset) */
    {0xffc00000, 0x39000000, "strb",  4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0x79000000, "strh",  4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0xb9000000, "str",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0xf9000000, "str",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0x3d000000, "str",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0xffc00000, 0x5d000000, "str",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Load/store pair (post-index) */
    {0x7fc00000, 0x28c00000, "stp",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7fc00000, 0x29c00000, "ldp",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7fc00000, 0x2cc00000, "stp",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7fc00000, 0x2dc00000, "ldp",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Load/store pair (pre-index) */
    {0x7fc00000, 0x29800000, "stp",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x7fc00000, 0x29c00000, "ldp",   4, A64_FORM_LS, A64_ARCH_V8A, A64_ARCH_V86A},

    /* Load literal */
    {0x9f000000, 0x18000000, "ldr",   4, A64_FORM_LIT, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9f000000, 0x1c000000, "ldr",   4, A64_FORM_LIT, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9f000000, 0x98000000, "ldrsw", 4, A64_FORM_LIT, A64_ARCH_V8A, A64_ARCH_V86A},

    /* FP instructions */
    {0x9e200c00, 0x1e204000, "fmov",  5, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9e200c00, 0x1e202800, "fadd",  5, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9e200c00, 0x1e203800, "fsub",  5, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9e200c00, 0x1e200800, "fmul",  5, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9e200c00, 0x1e201800, "fdiv",  5, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9e200c00, 0x1e20c000, "fabs",  5, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9e200c00, 0x1e214000, "fneg",  5, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9e200c00, 0x1e21c000, "fsqrt", 5, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},
    {0x9e200c00, 0x1e202000, "fcmp",  5, A64_FORM_REG, A64_ARCH_V8A, A64_ARCH_V86A},

    /* MTE instructions (ARMv8.5) */
    {0xff800000, 0xd9a00000, "stg",   6, A64_FORM_LS, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xff800000, 0xd9a00000, "ldg",   6, A64_FORM_LS, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xffe0fc00, 0x9ac01000, "irg",   6, A64_FORM_REG, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xffe0fc00, 0x9ac01000, "gmi",   6, A64_FORM_REG, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xffe0fc00, 0x9ac01000, "subp",  6, A64_FORM_REG, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xff800000, 0x91800000, "addg",  6, A64_FORM_IMM, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xff800000, 0x91800000, "subg",  6, A64_FORM_IMM, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xfff00000, 0xd9b00000, "stzgm", 6, A64_FORM_REG, A64_ARCH_V85A, A64_ARCH_V86A},
    {0xfff00000, 0xd9b00000, "ldzm",  6, A64_FORM_REG, A64_ARCH_V85A, A64_ARCH_V86A},

    /* PAC instructions (ARMv8.3) */
    {0xfffffbff, 0xdac123ff, "pacib", 6, A64_FORM_REG, A64_ARCH_V83A, A64_ARCH_V86A},
    {0xfffffbff, 0xdac113ff, "pacia", 6, A64_FORM_REG, A64_ARCH_V83A, A64_ARCH_V86A},
    {0xfffffbff, 0xdac133ff, "pacda", 6, A64_FORM_REG, A64_ARCH_V83A, A64_ARCH_V86A},
    {0xfffffbff, 0xdac143ff, "pacdb", 6, A64_FORM_REG, A64_ARCH_V83A, A64_ARCH_V86A},
    {0xfffffbff, 0xdac113ff, "autia", 6, A64_FORM_REG, A64_ARCH_V83A, A64_ARCH_V86A},
    {0xfffffbff, 0xdac123ff, "autib", 6, A64_FORM_REG, A64_ARCH_V83A, A64_ARCH_V86A},
    {0xffffffff, 0xd5031100, "xpaclri", 6, A64_FORM_NONE, A64_ARCH_V83A, A64_ARCH_V86A},
};

int a64_opcode_lookup(u32 insn, char *mnemonic, size_t mnemonic_size)
{
    int i;
    for (i = 0; i < (int)(sizeof(a64_opcode_db) /
                           sizeof(a64_opcode_db[0])); i++) {
        if ((insn & a64_opcode_db[i].mask) == a64_opcode_db[i].pattern) {
            if (mnemonic && mnemonic_size > 0) {
                strncpy(mnemonic, a64_opcode_db[i].mnemonic, mnemonic_size - 1);
                mnemonic[mnemonic_size - 1] = '\0';
            }
            return a64_opcode_db[i].arch_min;
        }
    }
    return -1;
}

int a64_insn_arch_version(u32 insn)
{
    int i;
    for (i = 0; i < (int)(sizeof(a64_opcode_db) /
                           sizeof(a64_opcode_db[0])); i++) {
        if ((insn & a64_opcode_db[i].mask) == a64_opcode_db[i].pattern) {
            return a64_opcode_db[i].arch_max;
        }
    }
    return -1;
}

bool a64_insn_is_supported(u32 insn, int arch_version)
{
    int i;
    for (i = 0; i < (int)(sizeof(a64_opcode_db) /
                           sizeof(a64_opcode_db[0])); i++) {
        if ((insn & a64_opcode_db[i].mask) == a64_opcode_db[i].pattern) {
            return a64_opcode_db[i].arch_min <= arch_version &&
                   a64_opcode_db[i].arch_max >= arch_version;
        }
    }
    return false;
}

int a64_analyze_prologue(const u32 *insns, int n_insns,
                          struct a64_frame_info *info)
{
    int i;

    if (!insns || !info) return -1;
    memset(info, 0, sizeof(*info));

    for (i = 0; i < n_insns && i < 32; i++) {
        u32 insn = insns[i];

        if ((insn & 0xffc00000) == 0xa9000000 ||
            (insn & 0xffc00000) == 0xa9800000 ||
            (insn & 0xffc00000) == 0xa9000000) {
            u8 rt2 = (insn >> 10) & 0x1f;
            u8 rt = insn & 0x1f;

            if (rt == 29 || rt == 30) info->has_fp = true;
            if (rt == 30 || rt2 == 30) info->has_lr = true;

            if (info->n_regs_saved < 16) {
                info->reg_save_list[info->n_regs_saved++] = rt;
            }
            if (info->n_regs_saved < 16 && rt != rt2) {
                info->reg_save_list[info->n_regs_saved++] = rt2;
            }
            info->saved_regs += 2;
        }

        if ((insn & 0xff800000) == 0xd1000000 ||
            (insn & 0xff800000) == 0xd3800000) {
            u8 rd = insn & 0x1f;
            if (rd == 31) {
                info->frame_size = ((insn >> 10) & 0xfff) <<
                                   (((insn >> 22) & 3) * 2);
                if (info->frame_size == 0)
                    info->frame_size = (insn >> 10) & 0xfff;
            }
        }

        if (insn == 0xd503233f || insn == 0xd503235f) {
            info->has_pac = true;
        }

        if (a64_insn_is_b(insn) || a64_insn_is_bl(insn) ||
            a64_insn_is_br(insn) || a64_insn_is_ret(insn))
            break;
    }

    return 0;
}

int a64_analyze_epilogue(const u32 *insns, int n_insns,
                          struct a64_frame_info *info)
{
    int i;

    if (!insns || !info) return -1;

    for (i = n_insns - 1; i >= 0 && i >= n_insns - 16; i--) {
        u32 insn = insns[i];

        if ((insn & 0xffc00000) == 0xa8c00000 ||
            (insn & 0xffc00000) == 0xa8c00000) {
            info->saved_regs += 2;
        }

        if ((insn & 0xff800000) == 0x91000000 ||
            (insn & 0xff800000) == 0x910003ff) {
            continue;
        }

        if (a64_insn_is_ret(insn))
            return 0;

        if (a64_insn_is_b(insn) || a64_insn_is_br(insn))
            break;
    }

    return 0;
}
