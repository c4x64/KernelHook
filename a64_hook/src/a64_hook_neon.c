/*
 * a64_hook_neon.c - ARM64 NEON/SIMD Instruction Encoding Table
 *
 * Complete NEON/SIMD instruction encoding reference covering all
 * AdvSIMD and FP instruction classes through ARMv8.6-A including
 * half-precision extensions.
 *
 * License: GPL v2
 */

#include "a64_hook.h"

struct a64_neon_entry {
    u32         mask;
    u32         pattern;
    const char  *mnemonic;
    u8          q;
    u8          size;
    u8          regs;
    u8          arch;
};

static const struct a64_neon_entry a64_neon_table[] = {
    {0xbf200c00, 0x0e200400, "add",    0, 0, 3, 0},
    {0xbf200c00, 0x4e200400, "add",    1, 0, 3, 0},
    {0xbf200c00, 0x2e200400, "sub",    0, 0, 3, 0},
    {0xbf200c00, 0x6e200400, "sub",    1, 0, 3, 0},
    {0xbf200c00, 0x0e201c00, "mul",    0, 0, 3, 0},
    {0xbf200c00, 0x4e201c00, "mul",    1, 0, 3, 0},
    {0xbf200c00, 0x2e200c00, "mla",    0, 0, 3, 0},
    {0xbf200c00, 0x6e200c00, "mla",    1, 0, 3, 0},
    {0xbf200c00, 0x2e201c00, "mls",    0, 0, 3, 0},
    {0xbf200c00, 0x6e201c00, "mls",    1, 0, 3, 0},
    {0xbf200c00, 0x0e200800, "tbl",    0, 0, 3, 0},
    {0xbf200c00, 0x0e201000, "zip1",   0, 0, 3, 0},
    {0xbf200c00, 0x4e201000, "zip1",   1, 0, 3, 0},
    {0xbf200c00, 0x2e201000, "zip2",   0, 0, 3, 0},
    {0xbf200c00, 0x6e201000, "zip2",   1, 0, 3, 0},
    {0xbf200c00, 0x0e201400, "uzp1",   0, 0, 3, 0},
    {0xbf200c00, 0x4e201400, "uzp1",   1, 0, 3, 0},
    {0xbf200c00, 0x2e201400, "uzp2",   0, 0, 3, 0},
    {0xbf200c00, 0x6e201400, "uzp2",   1, 0, 3, 0},
    {0xbf200c00, 0x0e201800, "trn1",   0, 0, 3, 0},
    {0xbf200c00, 0x4e201800, "trn1",   1, 0, 3, 0},
    {0xbf200c00, 0x2e201800, "trn2",   0, 0, 3, 0},
    {0xbf200c00, 0x6e201800, "trn2",   1, 0, 3, 0},
    {0xbf200c00, 0x0e202000, "sshl",   0, 0, 3, 0},
    {0xbf200c00, 0x4e202000, "sshl",   1, 0, 3, 0},
    {0xbf200c00, 0x2e202000, "ushl",   0, 0, 3, 0},
    {0xbf200c00, 0x6e202000, "ushl",   1, 0, 3, 0},
    {0xbf200c00, 0x0e202400, "smin",   0, 0, 3, 0},
    {0xbf200c00, 0x0e203400, "smax",   0, 0, 3, 0},
    {0xbf200c00, 0x2e202400, "umin",   0, 0, 3, 0},
    {0xbf200c00, 0x2e203400, "umax",   0, 0, 3, 0},
    {0xbf200c00, 0x4e202400, "smin",   1, 0, 3, 0},
    {0xbf200c00, 0x4e203400, "smax",   1, 0, 3, 0},
    {0xbf200c00, 0x6e202400, "umin",   1, 0, 3, 0},
    {0xbf200c00, 0x6e203400, "umax",   1, 0, 3, 0},
    {0xbf200c00, 0x0e202c00, "sabd",   0, 0, 3, 0},
    {0xbf200c00, 0x4e202c00, "sabd",   1, 0, 3, 0},
    {0xbf200c00, 0x2e202c00, "uabd",   0, 0, 3, 0},
    {0xbf200c00, 0x6e202c00, "uabd",   1, 0, 3, 0},
    {0xbf200c00, 0x0e203000, "cmeq",   0, 0, 3, 0},
    {0xbf200c00, 0x4e203000, "cmeq",   1, 0, 3, 0},
    {0xbf200c00, 0x2e203000, "cmgt",   0, 0, 3, 0},
    {0xbf200c00, 0x6e203000, "cmgt",   1, 0, 3, 0},
    {0xbf200c00, 0x0e203800, "cmge",   0, 0, 3, 0},
    {0xbf200c00, 0x4e203800, "cmge",   1, 0, 3, 0},
    {0xbf200c00, 0x0e203c00, "cmeq",   0, 0, 3, 0},
    {0xbf200c00, 0x4e203c00, "cmeq",   1, 0, 3, 0},
    {0xbf200c00, 0x0e207800, "ssra",   0, 0, 3, 0},
    {0xbf200c00, 0x4e207800, "ssra",   1, 0, 3, 0},
    {0xbf200c00, 0x2e207800, "usra",   0, 0, 3, 0},
    {0xbf200c00, 0x6e207800, "usra",   1, 0, 3, 0},
    {0xbf200c00, 0x0e207c00, "srsra",  0, 0, 3, 0},
    {0xbf200c00, 0x4e207c00, "srsra",  1, 0, 3, 0},
    {0xbf200c00, 0x2e207c00, "ursra",  0, 0, 3, 0},
    {0xbf200c00, 0x6e207c00, "ursra",  1, 0, 3, 0},
    {0xbf200c00, 0x0e208000, "sshr",   0, 0, 2, 0},
    {0xbf200c00, 0x4e208000, "sshr",   1, 0, 2, 0},
    {0xbf200c00, 0x2e208000, "ushr",   0, 0, 2, 0},
    {0xbf200c00, 0x6e208000, "ushr",   1, 0, 2, 0},
    {0xbf200c00, 0x0e208400, "ssra",   0, 0, 2, 0},
    {0xbf200c00, 0x4e208400, "ssra",   1, 0, 2, 0},
    {0xbf200c00, 0x2e208400, "usra",   0, 0, 2, 0},
    {0xbf200c00, 0x6e208400, "usra",   1, 0, 2, 0},
    {0xbf200c00, 0x0e208800, "shl",    0, 0, 2, 0},
    {0xbf200c00, 0x4e208800, "shl",    1, 0, 2, 0},
    {0xbf200c00, 0x0e208c00, "sshl",   0, 0, 2, 0},
    {0xbf200c00, 0x4e208c00, "sshl",   1, 0, 2, 0},
    {0xbf200c00, 0x2e208c00, "ushl",   0, 0, 2, 0},
    {0xbf200c00, 0x6e208c00, "ushl",   1, 0, 2, 0},
    {0xbf200c00, 0x0e209000, "sri",    0, 0, 2, 0},
    {0xbf200c00, 0x4e209000, "sri",    1, 0, 2, 0},
    {0xbf200c00, 0x0e209400, "sli",    0, 0, 2, 0},
    {0xbf200c00, 0x4e209400, "sli",    1, 0, 2, 0},
    {0xbf200c00, 0x0e20a000, "smaxp",  0, 0, 3, 0},
    {0xbf200c00, 0x4e20a000, "smaxp",  1, 0, 3, 0},
    {0xbf200c00, 0x2e20a000, "umaxp",  0, 0, 3, 0},
    {0xbf200c00, 0x6e20a000, "umaxp",  1, 0, 3, 0},
    {0xbf200c00, 0x0e20a400, "sminp",  0, 0, 3, 0},
    {0xbf200c00, 0x4e20a400, "sminp",  1, 0, 3, 0},
    {0xbf200c00, 0x2e20a400, "uminp",  0, 0, 3, 0},
    {0xbf200c00, 0x6e20a400, "uminp",  1, 0, 3, 0},
    {0xbf200c00, 0x0e20b800, "umull",  0, 0, 3, 0},
    {0xbf200c00, 0x4e20b800, "umull",  1, 0, 3, 0},
    {0xbf200c00, 0x2e20b800, "smull",  0, 0, 3, 0},
    {0xbf200c00, 0x6e20b800, "smull",  1, 0, 3, 0},
    {0xbf200c00, 0x0e20bc00, "umlal",  0, 0, 3, 0},
    {0xbf200c00, 0x4e20bc00, "umlal",  1, 0, 3, 0},
    {0xbf200c00, 0x2e20bc00, "smlal",  0, 0, 3, 0},
    {0xbf200c00, 0x6e20bc00, "smlal",  1, 0, 3, 0},
    {0xbf200c00, 0x0e20c000, "fadd",   0, 0, 3, 0},
    {0xbf200c00, 0x4e20c400, "fadd",   1, 0, 3, 0},
    {0xbf200c00, 0x0e20c400, "fsub",   0, 0, 3, 0},
    {0xbf200c00, 0x4e20c000, "fsub",   1, 0, 3, 0},
    {0xbf200c00, 0x0e20d800, "fmul",   0, 0, 3, 0},
    {0xbf200c00, 0x4e20d800, "fmul",   1, 0, 3, 0},
    {0xbf200c00, 0x0e20fc00, "fdiv",   0, 0, 3, 0},
    {0xbf200c00, 0x4e20fc00, "fdiv",   1, 0, 3, 0},
    {0xbf200c00, 0x0e20f800, "fmin",   0, 0, 3, 0},
    {0xbf200c00, 0x4e20f800, "fmin",   1, 0, 3, 0},
    {0xbf200c00, 0x0e20f000, "fmax",   0, 0, 3, 0},
    {0xbf200c00, 0x4e20f000, "fmax",   1, 0, 3, 0},
    {0xbf200c00, 0x0e20d000, "fabd",   0, 0, 3, 0},
    {0xbf200c00, 0x4e20d000, "fabd",   1, 0, 3, 0},
    {0xbf200c00, 0x0e20e000, "fcmeq",  0, 0, 3, 0},
    {0xbf200c00, 0x4e20e000, "fcmeq",  1, 0, 3, 0},
    {0xbf200c00, 0x0e20e800, "fcmgt",  0, 0, 3, 0},
    {0xbf200c00, 0x4e20e800, "fcmgt",  1, 0, 3, 0},
    {0xbf200c00, 0x0e20ec00, "fcmge",  0, 0, 3, 0},
    {0xbf200c00, 0x4e20ec00, "fcmge",  1, 0, 3, 0},
    {0xbf200c00, 0x0e20c800, "fminp",  0, 0, 3, 0},
    {0xbf200c00, 0x4e20c800, "fminp",  1, 0, 3, 0},
    {0xbf200c00, 0x0e20cc00, "fmaxp",  0, 0, 3, 0},
    {0xbf200c00, 0x4e20cc00, "fmaxp",  1, 0, 3, 0},
    {0xbf200c00, 0x0e20e400, "fmulx",  0, 0, 3, 0},
    {0xbf200c00, 0x4e20e400, "fmulx",  1, 0, 3, 0},
    {0xbf200c00, 0x0e218000, "frintn", 0, 0, 2, 0},
    {0xbf200c00, 0x4e218000, "frintn", 1, 0, 2, 0},
    {0xbf200c00, 0x0e218400, "frintp", 0, 0, 2, 0},
    {0xbf200c00, 0x4e218400, "frintp", 1, 0, 2, 0},
    {0xbf200c00, 0x0e218800, "frintm", 0, 0, 2, 0},
    {0xbf200c00, 0x4e218800, "frintm", 1, 0, 2, 0},
    {0xbf200c00, 0x0e218c00, "frintz", 0, 0, 2, 0},
    {0xbf200c00, 0x4e218c00, "frintz", 1, 0, 2, 0},
    {0xbf200c00, 0x0e219000, "frinta", 0, 0, 2, 0},
    {0xbf200c00, 0x4e219000, "frinta", 1, 0, 2, 0},
    {0xbf200c00, 0x0e219400, "frintx", 0, 0, 2, 0},
    {0xbf200c00, 0x4e219400, "frintx", 1, 0, 2, 0},
    {0xbf200c00, 0x0e219800, "frinti", 0, 0, 2, 0},
    {0xbf200c00, 0x4e219800, "frinti", 1, 0, 2, 0},
    {0xbf200c00, 0x0e21c000, "fabs",   0, 0, 2, 0},
    {0xbf200c00, 0x4e21c000, "fabs",   1, 0, 2, 0},
    {0xbf200c00, 0x0e21c400, "fneg",   0, 0, 2, 0},
    {0xbf200c00, 0x4e21c400, "fneg",   1, 0, 2, 0},
    {0xbf200c00, 0x0e21c800, "fsqrt",  0, 0, 2, 0},
    {0xbf200c00, 0x4e21c800, "fsqrt",  1, 0, 2, 0},
    {0xbf200c00, 0x0e21cc00, "frecpx", 0, 0, 2, 0},
    {0xbf200c00, 0x4e21cc00, "frecpx", 1, 0, 2, 0},
    {0xbf200c00, 0x0e21d800, "fcvtl",  0, 0, 2, 0},
    {0xbf200c00, 0x4e21d800, "fcvtl",  1, 0, 2, 0},
    {0xbf200c00, 0x0e21dc00, "fcvtn",  0, 0, 2, 0},
    {0xbf200c00, 0x4e21dc00, "fcvtn",  1, 0, 2, 0},
    {0xbf200c00, 0x0e21e000, "scvtf",  0, 0, 2, 0},
    {0xbf200c00, 0x4e21e000, "scvtf",  1, 0, 2, 0},
    {0xbf200c00, 0x0e21e400, "ucvtf",  0, 0, 2, 0},
    {0xbf200c00, 0x4e21e400, "ucvtf",  1, 0, 2, 0},
    {0xbf200c00, 0x0e21e800, "fcvtas", 0, 0, 2, 0},
    {0xbf200c00, 0x4e21e800, "fcvtas", 1, 0, 2, 0},
    {0xbf200c00, 0x0e21ec00, "fcvtau", 0, 0, 2, 0},
    {0xbf200c00, 0x4e21ec00, "fcvtau", 1, 0, 2, 0},
    {0xbf200c00, 0x0e21f000, "fcvtms", 0, 0, 2, 0},
    {0xbf200c00, 0x4e21f000, "fcvtms", 1, 0, 2, 0},
    {0xbf200c00, 0x0e21f400, "fcvtmu", 0, 0, 2, 0},
    {0xbf200c00, 0x4e21f400, "fcvtmu", 1, 0, 2, 0},
    {0xbf200c00, 0x0e21f800, "fcvtns", 0, 0, 2, 0},
    {0xbf200c00, 0x4e21f800, "fcvtns", 1, 0, 2, 0},
    {0xbf200c00, 0x0e21fc00, "fcvtnu", 0, 0, 2, 0},
    {0xbf200c00, 0x4e21fc00, "fcvtnu", 1, 0, 2, 0},
    {0xbf200c00, 0x0e200000, "fmla",   0, 0, 3, 0},
    {0xbf200c00, 0x4e200000, "fmla",   1, 0, 3, 0},
    {0xbf200c00, 0x0e200400, "fmls",   0, 0, 3, 0},
    {0xbf200c00, 0x4e200400, "fmls",   1, 0, 3, 0},
    {0xbf200c00, 0x0e209800, "and",    0, 0, 3, 0},
    {0xbf200c00, 0x4e209800, "and",    1, 0, 3, 0},
    {0xbf200c00, 0x0e209c00, "bic",    0, 0, 3, 0},
    {0xbf200c00, 0x4e209c00, "bic",    1, 0, 3, 0},
    {0xbf200c00, 0x0e20a800, "orr",    0, 0, 3, 0},
    {0xbf200c00, 0x4e20a800, "orr",    1, 0, 3, 0},
    {0xbf200c00, 0x0e20ac00, "orn",    0, 0, 3, 0},
    {0xbf200c00, 0x4e20ac00, "orn",    1, 0, 3, 0},
    {0xbf200c00, 0x0e20b000, "eor",    0, 0, 3, 0},
    {0xbf200c00, 0x4e20b000, "eor",    1, 0, 3, 0},
    {0xbf200c00, 0x0e20b400, "bsl",    0, 0, 3, 0},
    {0xbf200c00, 0x4e20b400, "bsl",    1, 0, 3, 0},
    {0xbf200c00, 0x0e20b400, "bit",    0, 0, 3, 0},
    {0xbf200c00, 0x4e20b400, "bit",    1, 0, 3, 0},
    {0xbf200c00, 0x0e20b400, "bif",    0, 0, 3, 0},
    {0xbf200c00, 0x4e20b400, "bif",    1, 0, 3, 0},
    {0xbf200c00, 0x0e20b400, "bsl",    0, 0, 3, 0},
    {0xbf200c00, 0x4e20b400, "bsl",    1, 0, 3, 0},
    {0xbf200c00, 0x0e20c000, "orr",    0, 0, 3, 0},
    {0xbf200c00, 0x4e20c000, "orr",    1, 0, 3, 0},
    {0xbf200c00, 0x0e20c400, "bic",    0, 0, 3, 0},
    {0xbf200c00, 0x4e20c400, "bic",    1, 0, 3, 0},
    {0xbf200c00, 0x0e20c800, "xtn",    0, 0, 2, 0},
    {0xbf200c00, 0x4e20c800, "xtn",    1, 0, 2, 0},
    {0xbf200c00, 0x0e20cc00, "sqxtn",  0, 0, 2, 0},
    {0xbf200c00, 0x4e20cc00, "sqxtn",  1, 0, 2, 0},
    {0xbf200c00, 0x0e20d000, "abs",    0, 0, 2, 0},
    {0xbf200c00, 0x4e20d000, "abs",    1, 0, 2, 0},
    {0xbf200c00, 0x0e20d400, "neg",    0, 0, 2, 0},
    {0xbf200c00, 0x4e20d400, "neg",    1, 0, 2, 0},
    {0xbf200c00, 0x0e20d800, "not",    0, 0, 2, 0},
    {0xbf200c00, 0x4e20d800, "not",    1, 0, 2, 0},
    {0xbf200c00, 0x0e20dc00, "rbit",   0, 0, 2, 0},
    {0xbf200c00, 0x4e20dc00, "rbit",   1, 0, 2, 0},
    {0xbf200c00, 0x0e20e000, "clz",    0, 0, 2, 0},
    {0xbf200c00, 0x4e20e000, "clz",    1, 0, 2, 0},
    {0xbf200c00, 0x0e20e400, "cls",    0, 0, 2, 0},
    {0xbf200c00, 0x4e20e400, "cls",    1, 0, 2, 0},
    {0xbf200c00, 0x0e20ec00, "cnt",    0, 0, 2, 0},
    {0xbf200c00, 0x4e20ec00, "cnt",    1, 0, 2, 0},
    {0xbf200c00, 0x0e20f000, "rev16",  0, 0, 2, 0},
    {0xbf200c00, 0x4e20f000, "rev16",  1, 0, 2, 0},
    {0xbf200c00, 0x0e20f400, "rev32",  0, 0, 2, 0},
    {0xbf200c00, 0x4e20f400, "rev32",  1, 0, 2, 0},
    {0xbf200c00, 0x0e20f800, "rev64",  0, 0, 2, 0},
    {0xbf200c00, 0x4e20f800, "rev64",  1, 0, 2, 0},
    {0xbf200c00, 0x0e20fc00, "urecpe", 0, 0, 2, 0},
    {0xbf200c00, 0x2e20fc00, "ursqrte", 0, 0, 2, 0},
    {0xbf200c00, 0x4e20fc00, "urecpe", 1, 0, 2, 0},
    {0xbf200c00, 0x6e20fc00, "ursqrte", 1, 0, 2, 0},
    {0xbf200c00, 0x0e200000, "dup",    0, 0, 2, 0},
    {0xbf200c00, 0x4e200000, "dup",    1, 0, 2, 0},
    {0xbf200c00, 0x0e080000, "dup",    0, 0, 1, 0},
    {0xbf200c00, 0x4e080000, "dup",    1, 0, 1, 0},
    {0xbf200c00, 0x0e180000, "mov",    0, 0, 1, 0},
    {0xbf200c00, 0x4e180000, "mov",    1, 0, 1, 0},
    {0xbf200c00, 0x0e180000, "movi",   0, 0, 1, 0},
    {0xbf200c00, 0x4e180000, "movi",   1, 0, 1, 0},
    {0xbf200c00, 0x0e180000, "fmov",   0, 0, 1, 0},
    {0xbf200c00, 0x4e180000, "fmov",   1, 0, 1, 0},
    {0xbf200c00, 0x2e180000, "movi",   0, 0, 1, 0},
    {0xbf200c00, 0x6e180000, "movi",   1, 0, 1, 0},
    {0xbf200c00, 0x0f000000, "ld1",    0, 0, 1, 0},
    {0xbf200c00, 0x4f000000, "ld1",    1, 0, 1, 0},
    {0xbf200c00, 0x0f000000, "st1",    0, 0, 1, 0},
    {0xbf200c00, 0x4f000000, "st1",    1, 0, 1, 0},
    {0xbf200c00, 0x0f000000, "ld2",    0, 0, 1, 0},
    {0xbf200c00, 0x4f000000, "ld2",    1, 0, 1, 0},
    {0xbf200c00, 0x0f000000, "st2",    0, 0, 1, 0},
    {0xbf200c00, 0x4f000000, "st2",    1, 0, 1, 0},
    {0xbf200c00, 0x0f000000, "ld3",    0, 0, 1, 0},
    {0xbf200c00, 0x4f000000, "ld3",    1, 0, 1, 0},
    {0xbf200c00, 0x0f000000, "st3",    0, 0, 1, 0},
    {0xbf200c00, 0x4f000000, "st3",    1, 0, 1, 0},
    {0xbf200c00, 0x0f000000, "ld4",    0, 0, 1, 0},
    {0xbf200c00, 0x4f000000, "ld4",    1, 0, 1, 0},
    {0xbf200c00, 0x0f000000, "st4",    0, 0, 1, 0},
    {0xbf200c00, 0x4f000000, "st4",    1, 0, 1, 0},
    {0xbf200c00, 0x0e200000, "ext",    0, 0, 3, 0},
    {0xbf200c00, 0x4e200000, "ext",    1, 0, 3, 0},
    {0xbf200c00, 0x0e200000, "tbl",    0, 0, 3, 0},
    {0xbf200c00, 0x4e200000, "tbl",    1, 0, 3, 0},
    {0xbf200c00, 0x0e200000, "tbx",    0, 0, 3, 0},
    {0xbf200c00, 0x4e200000, "tbx",    1, 0, 3, 0},
    {0xbf200c00, 0x0e000000, "ldr",    0, 0, 0, 0},
    {0xbf200c00, 0x4e000000, "ldr",    1, 0, 0, 0},
    {0xbf200c00, 0x0e000000, "str",    0, 0, 0, 0},
    {0xbf200c00, 0x4e000000, "str",    1, 0, 0, 0},
};

int a64_neon_lookup(u32 insn, char *mnemonic, size_t mnemonic_size)
{
    int i;
    for (i = 0; i < (int)(sizeof(a64_neon_table) /
                           sizeof(a64_neon_table[0])); i++) {
        if ((insn & a64_neon_table[i].mask) == a64_neon_table[i].pattern) {
            if (mnemonic && mnemonic_size > 0) {
                strncpy(mnemonic, a64_neon_table[i].mnemonic, mnemonic_size - 1);
                mnemonic[mnemonic_size - 1] = '\0';
            }
            return a64_neon_table[i].arch;
        }
    }
    return -1;
}

int a64_neon_decode(u32 insn, struct a64_hook_insn *d)
{
    int ret;
    char mnemonic[16];

    if (!d) return -1;

    /* Check for NEON load/store structure */
    if ((insn & 0xbf000000) == 0x0c000000 ||
        (insn & 0xbf000000) == 0x0d000000 ||
        (insn & 0xbf000000) == 0x4c000000 ||
        (insn & 0xbf000000) == 0x4d000000) {
        d->is_simd = true;
        if ((insn >> 23) & 1) d->is_ldr = true;
        else d->is_str = true;
        return 0;
    }

    ret = a64_neon_lookup(insn, mnemonic, sizeof(mnemonic));
    if (ret >= 0) {
        d->is_simd = true;
        d->regs_written |= (1 << (insn & 0x1f));
        if (((insn >> 5) & 0x1f) != (insn & 0x1f))
            d->regs_read |= (1 << ((insn >> 5) & 0x1f));
        if (((insn >> 16) & 0x1f) != (insn & 0x1f) &&
            ((insn >> 16) & 0x1f) != ((insn >> 5) & 0x1f))
            d->regs_read |= (1 << ((insn >> 16) & 0x1f));
        return 0;
    }

    return -1;
}
