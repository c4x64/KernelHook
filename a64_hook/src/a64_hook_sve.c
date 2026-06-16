/*
 * a64_hook_sve.c - ARM64 SVE/SVE2 Instruction Encoding Reference
 *
 * Covers the most commonly encountered SVE instructions from the
 * Scalable Vector Extension (ARMv8.2+) and SVE2 (ARMv8.6+).
 *
 * License: GPL v2
 */

#include "a64_hook.h"

struct a64_sve_entry {
    u32         mask;
    u32         pattern;
    const char  *mnemonic;
    u8          arch_min;
    u8          arch_max;
    u8          regs;
    u8          predicated;
};

static const struct a64_sve_entry a64_sve_table[] = {
    {0xfffffc00, 0x04e0e000, "add",        2, 6, 3, 0},
    {0xfffffc00, 0x04e06000, "add",        2, 6, 3, 0},
    {0xfffffc00, 0x04e08000, "mul",        2, 6, 3, 0},
    {0xfffffc00, 0x04e0a000, "sub",        2, 6, 3, 0},
    {0xfffffc00, 0x04e02000, "and",        2, 6, 3, 0},
    {0xfffffc00, 0x04e8e000, "add",        2, 6, 3, 0},
    {0xfffffc00, 0x04e86000, "add",        2, 6, 3, 0},
    {0xfffffc00, 0x04e88000, "mul",        2, 6, 3, 0},
    {0xfffffc00, 0x04e8a000, "sub",        2, 6, 3, 0},
    {0xfffffc00, 0x04e82000, "and",        2, 6, 3, 0},
    {0xfffffc00, 0x05e00000, "fadd",       2, 6, 3, 1},
    {0xfffffc00, 0x05e04000, "fsub",       2, 6, 3, 1},
    {0xfffffc00, 0x05e08000, "fmul",       2, 6, 3, 1},
    {0xfffffc00, 0x05e0c000, "fdiv",       2, 6, 3, 1},
    {0xfffffc00, 0x05e10000, "fmin",       2, 6, 3, 1},
    {0xfffffc00, 0x05e14000, "fmax",       2, 6, 3, 1},
    {0xfffffc00, 0x05e18000, "fabs",       2, 6, 2, 1},
    {0xfffffc00, 0x05e1c000, "fneg",       2, 6, 2, 1},
    {0xfffffc00, 0x05e20000, "fsqrt",      2, 6, 2, 1},
    {0xfffffc00, 0x05e24000, "frecpx",     2, 6, 2, 1},
    {0xfffffc00, 0x05e28000, "frintn",     2, 6, 2, 1},
    {0xfffffc00, 0x05e2c000, "frintp",     2, 6, 2, 1},
    {0xfffffc00, 0x05e30000, "frintm",     2, 6, 2, 1},
    {0xfffffc00, 0x05e34000, "frintz",     2, 6, 2, 1},
    {0xfffffc00, 0x05e38000, "frinta",     2, 6, 2, 1},
    {0xfffffc00, 0x05e3c000, "frintx",     2, 6, 2, 1},
    {0xfffffc00, 0x05e40000, "frinti",     2, 6, 2, 1},
    {0xfffffc00, 0x05e44000, "fcvt",       2, 6, 2, 1},
    {0xfffffc00, 0x05e48000, "scvtf",      2, 6, 2, 1},
    {0xfffffc00, 0x05e4c000, "ucvtf",      2, 6, 2, 1},
    {0xfffffc00, 0x05e50000, "fcvtas",     2, 6, 2, 1},
    {0xfffffc00, 0x05e54000, "fcvtau",     2, 6, 2, 1},
    {0xfffffc00, 0x05e58000, "fcvtms",     2, 6, 2, 1},
    {0xfffffc00, 0x05e5c000, "fcvtmu",     2, 6, 2, 1},
    {0xfffffc00, 0x05e60000, "fcvtns",     2, 6, 2, 1},
    {0xfffffc00, 0x05e64000, "fcvtnu",     2, 6, 2, 1},
    {0xfffffc00, 0x05e68000, "fcvtzs",     2, 6, 2, 1},
    {0xfffffc00, 0x05e6c000, "fcvtzu",     2, 6, 2, 1},
    {0xfffffc00, 0x04000000, "ld1b",       2, 6, 2, 1},
    {0xfffffc00, 0x04200000, "st1b",       2, 6, 2, 1},
    {0xfffffc00, 0x04000400, "ld1h",       2, 6, 2, 1},
    {0xfffffc00, 0x04200400, "st1h",       2, 6, 2, 1},
    {0xfffffc00, 0x04000800, "ld1w",       2, 6, 2, 1},
    {0xfffffc00, 0x04200800, "st1w",       2, 6, 2, 1},
    {0xfffffc00, 0x04000c00, "ld1d",       2, 6, 2, 1},
    {0xfffffc00, 0x04200c00, "st1d",       2, 6, 2, 1},
    {0xfffffc00, 0x04001000, "ld2b",       2, 6, 2, 1},
    {0xfffffc00, 0x04201000, "st2b",       2, 6, 2, 1},
    {0xfffffc00, 0x04001400, "ld2h",       2, 6, 2, 1},
    {0xfffffc00, 0x04201400, "st2h",       2, 6, 2, 1},
    {0xfffffc00, 0x04001800, "ld2w",       2, 6, 2, 1},
    {0xfffffc00, 0x04201800, "st2w",       2, 6, 2, 1},
    {0xfffffc00, 0x04001c00, "ld2d",       2, 6, 2, 1},
    {0xfffffc00, 0x04201c00, "st2d",       2, 6, 2, 1},
    {0xfffffc00, 0x04010000, "ldr",        2, 6, 2, 1},
    {0xfffffc00, 0x04210000, "str",        2, 6, 2, 1},
    {0xfffffc00, 0x04010400, "ldff1b",     2, 6, 2, 1},
    {0xfffffc00, 0x04010800, "ldnf1b",     2, 6, 2, 1},
    {0xfffffc00, 0x04010c00, "ldff1h",     2, 6, 2, 1},
    {0xfffffc00, 0x04011000, "ldnf1h",     2, 6, 2, 1},
    {0xfffffc00, 0x04011400, "ldff1w",     2, 6, 2, 1},
    {0xfffffc00, 0x04011800, "ldnf1w",     2, 6, 2, 1},
    {0xfffffc00, 0x04011c00, "ldff1d",     2, 6, 2, 1},
    {0xfffffc00, 0x04012000, "ldnf1d",     2, 6, 2, 1},
    {0xfffffc00, 0x04308000, "cntb",       2, 6, 1, 0},
    {0xfffffc00, 0x04308400, "cnth",       2, 6, 1, 0},
    {0xfffffc00, 0x04308800, "cntw",       2, 6, 1, 0},
    {0xfffffc00, 0x04308c00, "cntd",       2, 6, 1, 0},
    {0xfffffc00, 0x04309000, "incb",       2, 6, 1, 0},
    {0xfffffc00, 0x04309400, "inch",       2, 6, 1, 0},
    {0xfffffc00, 0x04309800, "incw",       2, 6, 1, 0},
    {0xfffffc00, 0x04309c00, "incd",       2, 6, 1, 0},
    {0xfffffc00, 0x0430a000, "decb",       2, 6, 1, 0},
    {0xfffffc00, 0x0430a400, "dech",       2, 6, 1, 0},
    {0xfffffc00, 0x0430a800, "decw",       2, 6, 1, 0},
    {0xfffffc00, 0x0430ac00, "decd",       2, 6, 1, 0},
    {0xfffffc00, 0x0430b000, "whilelo",    2, 6, 3, 0},
    {0xfffffc00, 0x0430b400, "whilehs",    2, 6, 3, 0},
    {0xfffffc00, 0x0430b800, "whilege",    2, 6, 3, 0},
    {0xfffffc00, 0x0430bc00, "whilehi",    2, 6, 3, 0},
    {0xfffffc00, 0x0430c000, "index",      2, 6, 3, 0},
    {0xfffffc00, 0x4430c000, "index",      2, 6, 3, 0},
    {0xfffffc00, 0x04e04000, "abs",        2, 6, 2, 0},
    {0xfffffc00, 0x04e0c000, "neg",        2, 6, 2, 0},
    {0xfffffc00, 0x04e14000, "not",        2, 6, 2, 0},
    {0xfffffc00, 0x04e0e000, "smax",       2, 6, 3, 0},
    {0xfffffc00, 0x04e0e000, "smin",       2, 6, 3, 0},
    {0xfffffc00, 0x04e0e000, "umax",       2, 6, 3, 0},
    {0xfffffc00, 0x04e0e000, "umin",       2, 6, 3, 0},
    {0xfffffc00, 0x04e0e000, "sabd",       2, 6, 3, 0},
    {0xfffffc00, 0x04e0e000, "uabd",       2, 6, 3, 0},
    {0xfffffc00, 0x04e0e000, "sdiv",       2, 6, 3, 0},
    {0xfffffc00, 0x04e0e000, "udiv",       2, 6, 3, 0},
    {0xfffffc00, 0x05e00000, "fmla",       2, 6, 3, 1},
    {0xfffffc00, 0x05e04000, "fmls",       2, 6, 3, 1},
    {0xfffffc00, 0x05e08000, "fnmla",      2, 6, 3, 1},
    {0xfffffc00, 0x05e0c000, "fnmls",      2, 6, 3, 1},
    {0xfffffc00, 0x05e10000, "fmad",       2, 6, 3, 1},
    {0xfffffc00, 0x05e14000, "fmsb",       2, 6, 3, 1},
    {0xfffffc00, 0x05e18000, "fnmad",      2, 6, 3, 1},
    {0xfffffc00, 0x05e1c000, "fnmsb",      2, 6, 3, 1},
    {0xfffffc00, 0x04e20000, "mla",        2, 6, 3, 0},
    {0xfffffc00, 0x04e24000, "mls",        2, 6, 3, 0},
    {0xfffffc00, 0x04e28000, "smulh",      2, 6, 3, 0},
    {0xfffffc00, 0x04e2c000, "umulh",      2, 6, 3, 0},
    {0xfffffc00, 0x04e30000, "pmul",       2, 6, 3, 0},
    {0xfffffc00, 0x04e34000, "cadd",       6, 6, 3, 0},
    {0xfffffc00, 0x04e38000, "cmla",       6, 6, 3, 0},
    {0xfffffc00, 0x04e3c000, "sclamp",     6, 6, 3, 0},
    {0xfffffc00, 0x04e40000, "uclamp",     6, 6, 3, 0},
    {0xffe01000, 0x64001000, "movprfx",    2, 6, 2, 0},
    {0xfffffc00, 0x05f00000, "faddv",      2, 6, 2, 1},
    {0xfffffc00, 0x05f00400, "fmaxnmv",    2, 6, 2, 1},
    {0xfffffc00, 0x05f00800, "fmaxv",      2, 6, 2, 1},
    {0xfffffc00, 0x05f00c00, "fminnmv",    2, 6, 2, 1},
    {0xfffffc00, 0x05f01000, "fminv",      2, 6, 2, 1},
    {0xfffffc00, 0x04f00000, "saddv",      2, 6, 2, 1},
    {0xfffffc00, 0x04f00400, "uaddv",      2, 6, 2, 1},
    {0xfffffc00, 0x04f00800, "smaxv",      2, 6, 2, 1},
    {0xfffffc00, 0x04f00c00, "umaxv",      2, 6, 2, 1},
    {0xfffffc00, 0x04f01000, "sminv",      2, 6, 2, 1},
    {0xfffffc00, 0x04f01400, "uminv",      2, 6, 2, 1},
    {0xfffffc00, 0x04f01800, "orv",        2, 6, 2, 1},
    {0xfffffc00, 0x04f01c00, "eorv",       2, 6, 2, 1},
    {0xfffffc00, 0x04f02000, "andv",       2, 6, 2, 1},
    {0xfffffc00, 0x04f02400, "lasta",      2, 6, 2, 1},
    {0xfffffc00, 0x04f02800, "lastb",      2, 6, 2, 1},
    {0xfffffc00, 0x04f02c00, "clasta",     2, 6, 3, 0},
    {0xfffffc00, 0x04f03000, "clastb",     2, 6, 3, 0},
    {0xfffffc00, 0x04f03400, "compact",    2, 6, 2, 1},
    {0xfffffc00, 0x04f03800, "splice",     2, 6, 3, 1},
    {0xfffffc00, 0x04f03c00, "ext",        2, 6, 3, 1},
    {0xfffffc00, 0x04f04000, "revb",       2, 6, 2, 0},
    {0xfffffc00, 0x04f04400, "revh",       2, 6, 2, 0},
    {0xfffffc00, 0x04f04800, "revw",       2, 6, 2, 0},
    {0xfffffc00, 0x04f04c00, "rbit",       2, 6, 2, 0},
    {0xfffffc00, 0x04f05000, "sxtb",       2, 6, 2, 0},
    {0xfffffc00, 0x04f05400, "sxth",       2, 6, 2, 0},
    {0xfffffc00, 0x04f05800, "sxtw",       2, 6, 2, 0},
    {0xfffffc00, 0x04f05c00, "uxtb",       2, 6, 2, 0},
    {0xfffffc00, 0x04f06000, "uxth",       2, 6, 2, 0},
    {0xfffffc00, 0x04f06400, "uxtw",       2, 6, 2, 0},
    {0xfffffc00, 0x04f06800, "cls",        2, 6, 2, 0},
    {0xfffffc00, 0x04f06c00, "clz",        2, 6, 2, 0},
    {0xfffffc00, 0x04f07000, "cnt",        2, 6, 2, 0},
    {0xfffffc00, 0x04f07400, "cnot",       2, 6, 2, 0},
    {0xfffffc00, 0x04f07800, "fabs",       2, 6, 2, 0},
    {0xfffffc00, 0x04f07c00, "fneg",       2, 6, 2, 0},
    {0xfffffc00, 0x04f08000, "rdffr",      2, 6, 1, 0},
    {0xfffffc00, 0x04f08400, "wrffr",      2, 6, 2, 0},
    {0xfffffc00, 0x04f08800, "setffr",     2, 6, 0, 0},
    {0xfffffc00, 0x04f08c00, "ptrue",      2, 6, 2, 0},
    {0xfffffc00, 0x04f09000, "pfalse",     2, 6, 2, 0},
    {0xfffffc00, 0x04f09400, "ptest",      2, 6, 1, 0},
    {0xfffffc00, 0x04f09800, "pnext",      2, 6, 2, 0},
    {0xfffffc00, 0x04012400, "ldff1b",     2, 6, 2, 1},
    {0xfffffc00, 0x04212400, "st1b",       2, 6, 2, 1},
    {0xfffffc00, 0x04012800, "ldnf1b",     2, 6, 2, 1},
    {0xfffffc00, 0x04212800, "st1h",       2, 6, 2, 1},
    {0xfffffc00, 0x04012c00, "ldff1h",     2, 6, 2, 1},
    {0xfffffc00, 0x04212c00, "st1w",       2, 6, 2, 1},
    {0xfffffc00, 0x04013000, "ldnf1h",     2, 6, 2, 1},
    {0xfffffc00, 0x04213000, "st1d",       2, 6, 2, 1},
    {0xfffffc00, 0x04013400, "ldff1w",     2, 6, 2, 1},
    {0xfffffc00, 0x04213400, "st2b",       2, 6, 2, 1},
    {0xfffffc00, 0x04013800, "ldnf1w",     2, 6, 2, 1},
    {0xfffffc00, 0x04213800, "st2h",       2, 6, 2, 1},
    {0xfffffc00, 0x04013c00, "ldff1d",     2, 6, 2, 1},
    {0xfffffc00, 0x04213c00, "st2w",       2, 6, 2, 1},
    {0xfffffc00, 0x04014000, "ldnf1d",     2, 6, 2, 1},
    {0xfffffc00, 0x04214000, "st2d",       2, 6, 2, 1},
};

int a64_sve_lookup(u32 insn, char *mnemonic, size_t mnemonic_size)
{
    int i;
    for (i = 0; i < (int)(sizeof(a64_sve_table) /
                           sizeof(a64_sve_table[0])); i++) {
        if ((insn & a64_sve_table[i].mask) == a64_sve_table[i].pattern) {
            if (mnemonic && mnemonic_size > 0) {
                strncpy(mnemonic, a64_sve_table[i].mnemonic, mnemonic_size - 1);
                mnemonic[mnemonic_size - 1] = '\0';
            }
            return a64_sve_table[i].arch_min;
        }
    }
    return -1;
}

int a64_sve_decode(u32 insn, struct a64_hook_insn *d)
{
    char mnemonic[16];
    int ret;

    if (!d) return -1;

    ret = a64_sve_lookup(insn, mnemonic, sizeof(mnemonic));
    if (ret >= 0) {
        d->is_simd = true;
        return 0;
    }

    return -1;
}
