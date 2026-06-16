/*
 * a64_hook_crypto.c - ARM64 Crypto Extension Instruction Table
 *
 * Encodings for AES, SHA1/2, SHA3, SM3, SM4 cryptographic
 * instructions available from ARMv8.0 through ARMv8.6-A.
 *
 * License: GPL v2
 */

#include "a64_hook.h"

struct a64_crypto_entry {
    u32         mask;
    u32         pattern;
    const char  *mnemonic;
    u8          arch_min;
    u8          arch_max;
    u8          regs;
};

static const struct a64_crypto_entry a64_crypto_table[] = {
    {0xff200c00, 0x0e200000, "aese",     0, 6, 2},
    {0xff200c00, 0x4e200000, "aese",     0, 6, 2},
    {0xff200c00, 0x2e200000, "aesd",     0, 6, 2},
    {0xff200c00, 0x6e200000, "aesd",     0, 6, 2},
    {0xff200c00, 0x0e200800, "aesmc",    0, 6, 2},
    {0xff200c00, 0x4e200800, "aesmc",    0, 6, 2},
    {0xff200c00, 0x2e200800, "aesimc",   0, 6, 2},
    {0xff200c00, 0x6e200800, "aesimc",   0, 6, 2},
    {0xff200c00, 0x0e200400, "sha1c",    0, 6, 3},
    {0xff200c00, 0x4e200400, "sha1c",    0, 6, 3},
    {0xff200c00, 0x0e200400, "sha1m",    0, 6, 3},
    {0xff200c00, 0x4e200400, "sha1m",    0, 6, 3},
    {0xff200c00, 0x0e200400, "sha1p",    0, 6, 3},
    {0xff200c00, 0x4e200400, "sha1p",    0, 6, 3},
    {0xff200c00, 0x0e200400, "sha1h",    0, 6, 2},
    {0xff200c00, 0x4e200400, "sha1h",    0, 6, 2},
    {0xff200c00, 0x0e200400, "sha1su0",  0, 6, 3},
    {0xff200c00, 0x4e200400, "sha1su0",  0, 6, 3},
    {0xff200c00, 0x0e200400, "sha1su1",  0, 6, 3},
    {0xff200c00, 0x4e200400, "sha1su1",  0, 6, 3},
    {0xff200c00, 0x0e200400, "sha256h",  0, 6, 3},
    {0xff200c00, 0x4e200400, "sha256h",  0, 6, 3},
    {0xff200c00, 0x0e200400, "sha256h2", 0, 6, 3},
    {0xff200c00, 0x4e200400, "sha256h2", 0, 6, 3},
    {0xff200c00, 0x0e200400, "sha256su0", 0, 6, 3},
    {0xff200c00, 0x4e200400, "sha256su0", 0, 6, 3},
    {0xff200c00, 0x0e200400, "sha256su1", 0, 6, 3},
    {0xff200c00, 0x4e200400, "sha256su1", 0, 6, 3},
    {0xff200c00, 0x0e200400, "sha512h",  3, 6, 3},
    {0xff200c00, 0x4e200400, "sha512h",  3, 6, 3},
    {0xff200c00, 0x0e200400, "sha512h2", 3, 6, 3},
    {0xff200c00, 0x4e200400, "sha512h2", 3, 6, 3},
    {0xff200c00, 0x0e200400, "sha512su0", 3, 6, 3},
    {0xff200c00, 0x4e200400, "sha512su0", 3, 6, 3},
    {0xff200c00, 0x0e200400, "sha512su1", 3, 6, 3},
    {0xff200c00, 0x4e200400, "sha512su1", 3, 6, 3},
    {0xff200c00, 0x0e200400, "sha3",     3, 6, 3},
    {0xff200c00, 0x4e200400, "sha3",     3, 6, 3},
    {0xff200c00, 0x0e200400, "sm3",      3, 6, 3},
    {0xff200c00, 0x4e200400, "sm3",      3, 6, 3},
    {0xff200c00, 0x0e200400, "sm4",      3, 6, 3},
    {0xff200c00, 0x4e200400, "sm4",      3, 6, 3},
    {0xfffffc00, 0xcec08000, "crc32b",   0, 6, 3},
    {0xfffffc00, 0xcec0c000, "crc32h",   0, 6, 3},
    {0xfffffc00, 0xcec10000, "crc32w",   0, 6, 3},
    {0xfffffc00, 0xcec14000, "crc32x",   0, 6, 3},
    {0xfffffc00, 0xcec22000, "crc32cb",  0, 6, 3},
    {0xfffffc00, 0xcec26000, "crc32ch",  0, 6, 3},
    {0xfffffc00, 0xcec2a000, "crc32cw",  0, 6, 3},
    {0xfffffc00, 0xcec2e000, "crc32cx",  0, 6, 3},
};

int a64_crypto_lookup(u32 insn, char *mnemonic, size_t mnemonic_size)
{
    int i;
    for (i = 0; i < (int)(sizeof(a64_crypto_table) /
                           sizeof(a64_crypto_table[0])); i++) {
        if ((insn & a64_crypto_table[i].mask) == a64_crypto_table[i].pattern) {
            if (mnemonic && mnemonic_size > 0) {
                strncpy(mnemonic, a64_crypto_table[i].mnemonic, mnemonic_size - 1);
                mnemonic[mnemonic_size - 1] = '\0';
            }
            return a64_crypto_table[i].arch_min;
        }
    }
    return -1;
}

int a64_crypto_decode(u32 insn, struct a64_hook_insn *d)
{
    char mnemonic[16];
    int ret;

    if (!d) return -1;

    ret = a64_crypto_lookup(insn, mnemonic, sizeof(mnemonic));
    if (ret >= 0) {
        d->is_simd = true;
        return 0;
    }

    return -1;
}
