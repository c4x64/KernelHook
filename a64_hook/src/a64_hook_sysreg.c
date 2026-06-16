/*
 * a64_hook_sysreg.c - ARM64 System Register Definitions
 *
 * Comprehensive ARM64 system register table including register
 * encoding, access permissions, and trap behavior for all
 * defined system registers through ARMv8.6-A.
 *
 * Used by the hook engine to analyze MSR/MRS instructions
 * and handle system register accesses in hooked code.
 *
 * License: GPL v2
 */

#include "a64_hook.h"

struct a64_sysreg_entry {
    const char *name;
    u16        op0;
    u8         op1;
    u8         crn;
    u8         crm;
    u8         op2;
    u8         access;
    u8         el;
};

enum a64_sysreg_access {
    SYSREG_RW  = 0,
    SYSREG_RO  = 1,
    SYSREG_WO  = 2,
};

static const struct a64_sysreg_entry a64_sysreg_table[] = {
    {"midr_el1",         0x03, 0, 0, 0, 0, SYSREG_RO, 1},
    {"ctr_el0",          0x03, 3, 0, 0, 1, SYSREG_RO, 0},
    {"mpidr_el1",        0x03, 0, 0, 0, 5, SYSREG_RO, 1},
    {"revidr_el1",       0x03, 0, 0, 0, 6, SYSREG_RO, 1},
    {"aidr_el1",         0x03, 1, 0, 0, 0, SYSREG_RO, 1},
    {"dczid_el0",        0x03, 3, 0, 0, 7, SYSREG_RO, 0},
    {"ccsidr_el1",       0x03, 1, 0, 0, 0, SYSREG_RO, 1},
    {"clidr_el1",        0x03, 1, 0, 0, 1, SYSREG_RO, 1},
    {"csselr_el1",       0x03, 2, 0, 0, 0, SYSREG_RW, 1},
    {"sctlr_el1",        0x03, 0, 1, 0, 0, SYSREG_RW, 1},
    {"sctlr_el2",        0x03, 4, 1, 0, 0, SYSREG_RW, 2},
    {"sctlr_el3",        0x03, 6, 1, 0, 0, SYSREG_RW, 3},
    {"actlr_el1",        0x03, 0, 1, 0, 1, SYSREG_RW, 1},
    {"actlr_el2",        0x03, 4, 1, 0, 1, SYSREG_RW, 2},
    {"actlr_el3",        0x03, 6, 1, 0, 1, SYSREG_RW, 3},
    {"cpacr_el1",        0x03, 0, 1, 0, 2, SYSREG_RW, 1},
    {"cptr_el2",         0x03, 4, 1, 1, 2, SYSREG_RW, 2},
    {"cptr_el3",         0x03, 6, 1, 1, 2, SYSREG_RW, 3},
    {"scr_el3",           0x03, 6, 1, 1, 0, SYSREG_RW, 3},
    {"hcr_el2",           0x03, 4, 1, 1, 0, SYSREG_RW, 2},
    {"mdcr_el2",         0x03, 4, 1, 1, 1, SYSREG_RW, 2},
    {"mdcr_el3",         0x03, 6, 1, 3, 1, SYSREG_RW, 3},
    {"ttbr0_el1",        0x03, 0, 2, 0, 0, SYSREG_RW, 1},
    {"ttbr1_el1",        0x03, 0, 2, 0, 1, SYSREG_RW, 1},
    {"ttbr0_el2",        0x03, 4, 2, 0, 0, SYSREG_RW, 2},
    {"ttbr1_el2",        0x03, 4, 2, 0, 1, SYSREG_RW, 2},
    {"ttbr0_el3",        0x03, 6, 2, 0, 0, SYSREG_RW, 3},
    {"tcr_el1",          0x03, 0, 2, 0, 2, SYSREG_RW, 1},
    {"tcr_el2",          0x03, 4, 2, 0, 2, SYSREG_RW, 2},
    {"tcr_el3",          0x03, 6, 2, 0, 2, SYSREG_RW, 3},
    {"vttbr_el2",        0x03, 4, 2, 1, 0, SYSREG_RW, 2},
    {"vtcr_el2",         0x03, 4, 2, 1, 2, SYSREG_RW, 2},
    {"spsr_el1",         0x03, 0, 4, 0, 0, SYSREG_RW, 1},
    {"spsr_el2",         0x03, 4, 4, 0, 0, SYSREG_RW, 2},
    {"spsr_el3",         0x03, 6, 4, 0, 0, SYSREG_RW, 3},
    {"elr_el1",          0x03, 0, 4, 0, 1, SYSREG_RW, 1},
    {"elr_el2",          0x03, 4, 4, 0, 1, SYSREG_RW, 2},
    {"elr_el3",          0x03, 6, 4, 0, 1, SYSREG_RW, 3},
    {"sp_el0",           0x03, 0, 4, 1, 0, SYSREG_RW, 1},
    {"spsel",            0x03, 0, 4, 2, 0, SYSREG_RW, 1},
    {"nzcv",             0x03, 3, 4, 2, 0, SYSREG_RW, 0},
    {"daif",             0x03, 3, 4, 2, 1, SYSREG_RW, 0},
    {"currentel",        0x03, 0, 4, 2, 2, SYSREG_RO, 1},
    {"pan",              0x03, 0, 4, 2, 3, SYSREG_RW, 1},
    {"uao",              0x03, 0, 4, 2, 4, SYSREG_RW, 1},
    {"esr_el1",          0x03, 0, 5, 2, 0, SYSREG_RW, 1},
    {"esr_el2",          0x03, 4, 5, 2, 0, SYSREG_RW, 2},
    {"esr_el3",          0x03, 6, 5, 2, 0, SYSREG_RW, 3},
    {"far_el1",          0x03, 0, 6, 0, 0, SYSREG_RW, 1},
    {"far_el2",          0x03, 4, 6, 0, 0, SYSREG_RW, 2},
    {"far_el3",          0x03, 6, 6, 0, 0, SYSREG_RW, 3},
    {"par_el1",          0x03, 0, 7, 4, 0, SYSREG_RW, 1},
    {"mair_el1",         0x03, 0, 10, 2, 0, SYSREG_RW, 1},
    {"mair_el2",         0x03, 4, 10, 2, 0, SYSREG_RW, 2},
    {"mair_el3",         0x03, 6, 10, 2, 0, SYSREG_RW, 3},
    {"amair_el1",        0x03, 0, 10, 3, 0, SYSREG_RW, 1},
    {"amair_el2",        0x03, 4, 10, 3, 0, SYSREG_RW, 2},
    {"amair_el3",        0x03, 6, 10, 3, 0, SYSREG_RW, 3},
    {"vbar_el1",         0x03, 0, 12, 0, 0, SYSREG_RW, 1},
    {"vbar_el2",         0x03, 4, 12, 0, 0, SYSREG_RW, 2},
    {"vbar_el3",         0x03, 6, 12, 0, 0, SYSREG_RW, 3},
    {"rmr_el1",          0x03, 0, 12, 0, 1, SYSREG_RW, 1},
    {"rmr_el2",          0x03, 4, 12, 0, 1, SYSREG_RW, 2},
    {"rmr_el3",          0x03, 6, 12, 0, 1, SYSREG_RW, 3},
    {"isr_el1",          0x03, 0, 12, 1, 0, SYSREG_RO, 1},
    {"contextidr_el1",   0x03, 0, 13, 0, 1, SYSREG_RW, 1},
    {"tpidr_el0",        0x03, 3, 13, 0, 2, SYSREG_RW, 0},
    {"tpidr_el1",        0x03, 0, 13, 0, 4, SYSREG_RW, 1},
    {"tpidr_el2",        0x03, 4, 13, 0, 2, SYSREG_RW, 2},
    {"tpidr_el3",        0x03, 6, 13, 0, 2, SYSREG_RW, 3},
    {"tpidrro_el0",      0x03, 3, 13, 0, 3, SYSREG_RO, 0},
    {"cntfrq_el0",       0x03, 3, 14, 0, 0, SYSREG_RW, 0},
    {"cntpct_el0",       0x03, 3, 14, 0, 1, SYSREG_RO, 0},
    {"cntvct_el0",       0x03, 3, 14, 0, 2, SYSREG_RO, 0},
    {"cntvoff_el2",      0x03, 4, 14, 0, 3, SYSREG_RW, 2},
    {"cntkctl_el1",      0x03, 0, 14, 1, 0, SYSREG_RW, 1},
    {"cntp_tval_el0",    0x03, 3, 14, 2, 0, SYSREG_RW, 0},
    {"cntp_ctl_el0",     0x03, 3, 14, 2, 1, SYSREG_RW, 0},
    {"cntp_cval_el0",    0x03, 3, 14, 2, 2, SYSREG_RW, 0},
    {"cntv_tval_el0",    0x03, 3, 14, 3, 0, SYSREG_RW, 0},
    {"cntv_ctl_el0",     0x03, 3, 14, 3, 1, SYSREG_RW, 0},
    {"cntv_cval_el0",    0x03, 3, 14, 3, 2, SYSREG_RW, 0},
    {"cntpst_tval_el0",  0x03, 3, 14, 4, 0, SYSREG_RW, 0},
    {"cntpst_ctl_el0",   0x03, 3, 14, 4, 1, SYSREG_RW, 0},
    {"cntpst_cval_el0",  0x03, 3, 14, 4, 2, SYSREG_RW, 0},
    {"cntvst_tval_el0",  0x03, 3, 14, 5, 0, SYSREG_RW, 0},
    {"cntvst_ctl_el0",   0x03, 3, 14, 5, 1, SYSREG_RW, 0},
    {"cntvst_cval_el0",  0x03, 3, 14, 5, 2, SYSREG_RW, 0},
    {"pmcr_el0",         0x03, 3, 9, 12, 0, SYSREG_RW, 0},
    {"pmcntenset_el0",   0x03, 3, 9, 12, 1, SYSREG_RW, 0},
    {"pmcntenclr_el0",   0x03, 3, 9, 12, 2, SYSREG_RW, 0},
    {"pmovsr_el0",       0x03, 3, 9, 12, 3, SYSREG_RW, 0},
    {"pmswinc_el0",      0x03, 3, 9, 12, 4, SYSREG_WO, 0},
    {"pmselr_el0",       0x03, 3, 9, 12, 5, SYSREG_RW, 0},
    {"pmceid0_el0",      0x03, 3, 9, 12, 6, SYSREG_RO, 0},
    {"pmceid1_el0",      0x03, 3, 9, 12, 7, SYSREG_RO, 0},
    {"pmccntr_el0",      0x03, 3, 9, 13, 0, SYSREG_RW, 0},
    {"pmxevtyper_el0",   0x03, 3, 9, 13, 1, SYSREG_RW, 0},
    {"pmxevcntr_el0",    0x03, 3, 9, 13, 2, SYSREG_RW, 0},
    {"pmuserenr_el0",    0x03, 3, 9, 14, 0, SYSREG_RW, 0},
    {"pmintenset_el1",   0x03, 0, 9, 14, 1, SYSREG_RW, 1},
    {"pmintenclr_el1",   0x03, 0, 9, 14, 2, SYSREG_RW, 1},
    {"pmovsset_el0",     0x03, 3, 9, 14, 3, SYSREG_RW, 0},
    {"pmevtyper0_el0",   0x03, 3, 9, 4, 0, SYSREG_RW, 0},
    {"pmevtyper1_el0",   0x03, 3, 9, 4, 1, SYSREG_RW, 0},
    {"pmevtyper2_el0",   0x03, 3, 9, 4, 2, SYSREG_RW, 0},
    {"pmevtyper3_el0",   0x03, 3, 9, 4, 3, SYSREG_RW, 0},
    {"pmevtyper4_el0",   0x03, 3, 9, 4, 4, SYSREG_RW, 0},
    {"pmevtyper5_el0",   0x03, 3, 9, 4, 5, SYSREG_RW, 0},
    {"trfcr_el1",        0x03, 0, 1, 2, 0, SYSREG_RW, 1},
    {"trfcr_el2",        0x03, 4, 1, 2, 0, SYSREG_RW, 2},
    {"apgakeyhi_el1",    0x03, 0, 2, 1, 0, SYSREG_RW, 1},
    {"apgakeylo_el1",    0x03, 0, 2, 1, 1, SYSREG_RW, 1},
    {"apibkeyhi_el1",    0x03, 0, 2, 2, 0, SYSREG_RW, 1},
    {"apibkeylo_el1",    0x03, 0, 2, 2, 1, SYSREG_RW, 1},
    {"apdakeyhi_el1",    0x03, 0, 2, 3, 0, SYSREG_RW, 1},
    {"apdakeylo_el1",    0x03, 0, 2, 3, 1, SYSREG_RW, 1},
    {"apdbkeyhi_el1",    0x03, 0, 2, 4, 0, SYSREG_RW, 1},
    {"apdbkeylo_el1",    0x03, 0, 2, 4, 1, SYSREG_RW, 1},
    {"apgakeyhi_el2",    0x03, 4, 2, 1, 0, SYSREG_RW, 2},
    {"apgakeylo_el2",    0x03, 4, 2, 1, 1, SYSREG_RW, 2},
    {"apibkeyhi_el2",    0x03, 4, 2, 2, 0, SYSREG_RW, 2},
    {"apibkeylo_el2",    0x03, 4, 2, 2, 1, SYSREG_RW, 2},
    {"apdakeyhi_el2",    0x03, 4, 2, 3, 0, SYSREG_RW, 2},
    {"apdakeylo_el2",    0x03, 4, 2, 3, 1, SYSREG_RW, 2},
    {"apdbkeyhi_el2",    0x03, 4, 2, 4, 0, SYSREG_RW, 2},
    {"apdbkeylo_el2",    0x03, 4, 2, 4, 1, SYSREG_RW, 2},
    {"gcr_el1",          0x03, 0, 1, 0, 6, SYSREG_RW, 1},
    {"rgsr_el1",         0x03, 0, 1, 0, 7, SYSREG_RW, 1},
    {"disr_el1",         0x03, 0, 12, 1, 1, SYSREG_RW, 1},
    {"vdisr_el2",        0x03, 4, 12, 1, 1, SYSREG_RW, 2},
    {"vsessr_el2",       0x03, 4, 12, 1, 2, SYSREG_RW, 2},
    {"hpfar_el2",        0x03, 4, 7, 4, 0, SYSREG_RW, 2},
    {"afsr0_el1",        0x03, 0, 5, 1, 0, SYSREG_RW, 1},
    {"afsr1_el1",        0x03, 0, 5, 1, 1, SYSREG_RW, 1},
    {"afsr0_el2",        0x03, 4, 5, 1, 0, SYSREG_RW, 2},
    {"afsr1_el2",        0x03, 4, 5, 1, 1, SYSREG_RW, 2},
    {"afsr0_el3",        0x03, 6, 5, 1, 0, SYSREG_RW, 3},
    {"afsr1_el3",        0x03, 6, 5, 1, 1, SYSREG_RW, 3},
    {"ifsr32_el2",       0x03, 4, 5, 0, 1, SYSREG_RW, 2},
    {"fpcr",             0x03, 3, 4, 4, 0, SYSREG_RW, 0},
    {"fpsr",             0x03, 3, 4, 4, 1, SYSREG_RW, 0},
    {"dspsr_el0",        0x03, 3, 5, 0, 0, SYSREG_RW, 0},
    {"dlr_el0",          0x03, 3, 5, 1, 0, SYSREG_RW, 0},
    {"sder_el3",         0x03, 6, 1, 3, 0, SYSREG_RW, 3},
    {"mds_el1",          0x03, 0, 9, 2, 2, SYSREG_RW, 1},
    {"pfar_el1",         0x03, 0, 6, 0, 1, SYSREG_RW, 1},
    {"pmscr_el1",        0x03, 0, 9, 9, 0, SYSREG_RW, 1},
    {"pmsicr_el1",       0x03, 0, 9, 9, 2, SYSREG_RW, 1},
    {"pmsirr_el1",       0x03, 0, 9, 9, 4, SYSREG_WO, 1},
    {"pmslatfr_el1",     0x03, 0, 9, 9, 6, SYSREG_RO, 1},
    {"pmsidr_el1",       0x03, 0, 9, 9, 7, SYSREG_RO, 1},
    {"pmevcnr0_el0",     0x03, 3, 9, 0, 0, SYSREG_RW, 0},
    {"pmevcnr1_el0",     0x03, 3, 9, 0, 1, SYSREG_RW, 0},
    {"pmevcnr2_el0",     0x03, 3, 9, 0, 2, SYSREG_RW, 0},
    {"pmevcnr3_el0",     0x03, 3, 9, 0, 3, SYSREG_RW, 0},
    {"pmevcnr4_el0",     0x03, 3, 9, 0, 4, SYSREG_RW, 0},
    {"pmevcnr5_el0",     0x03, 3, 9, 0, 5, SYSREG_RW, 0},
    {"zcr_el1",          0x03, 0, 1, 2, 0, SYSREG_RW, 1},
    {"zcr_el2",          0x03, 4, 1, 2, 0, SYSREG_RW, 2},
    {"zcr_el3",          0x03, 6, 1, 2, 0, SYSREG_RW, 3},
    {"smcr_el1",         0x03, 0, 1, 2, 0, SYSREG_RW, 1},
    {"smcr_el2",         0x03, 4, 1, 2, 0, SYSREG_RW, 2},
    {"smcr_el3",         0x03, 6, 1, 2, 0, SYSREG_RW, 3},
    {"smpri_el1",        0x03, 0, 1, 2, 4, SYSREG_RW, 1},
};

int a64_sysreg_lookup(u16 op0, u8 op1, u8 crn, u8 crm, u8 op2,
                       struct a64_sysreg_entry *out)
{
    int i;
    for (i = 0; i < (int)(sizeof(a64_sysreg_table) /
                           sizeof(a64_sysreg_table[0])); i++) {
        const struct a64_sysreg_entry *e = &a64_sysreg_table[i];
        if (e->op0 == op0 && e->op1 == op1 && e->crn == crn &&
            e->crm == crm && e->op2 == op2) {
            if (out) *out = *e;
            return 0;
        }
    }
    return -1;
}

int a64_sysreg_lookup_by_name(const char *name,
                               struct a64_sysreg_entry *out)
{
    int i;
    if (!name) return -1;
    for (i = 0; i < (int)(sizeof(a64_sysreg_table) /
                           sizeof(a64_sysreg_table[0])); i++) {
        const struct a64_sysreg_entry *e = &a64_sysreg_table[i];
        if (strcmp(e->name, name) == 0) {
            if (out) *out = *e;
            return 0;
        }
    }
    return -1;
}

u32 a64_sysreg_encode(const struct a64_sysreg_entry *reg)
{
    if (!reg) return 0;
    return (reg->op0 << 14) | (reg->op1 << 11) |
           (reg->crn << 7) | (reg->crm << 3) | reg->op2;
}

int a64_decode_mrs_mrs(u32 insn, struct a64_sysreg_entry *reg)
{
    u16 op0;
    u8 op1, crn, crm, op2;

    if ((insn & 0xfe000000) != 0xd5000000)
        return -1;

    op2 = (insn >> 0) & 0x7;
    crm = (insn >> 8) & 0x0f;
    crn = (insn >> 16) & 0x0f;
    op1 = (insn >> 11) & 0x07;
    op0 = ((insn >> 19) & 0x01) | ((insn >> 21) & 0x0e);

    return a64_sysreg_lookup(op0, op1, crn, crm, op2, reg);
}

int a64_sysreg_count(void)
{
    return (int)(sizeof(a64_sysreg_table) /
                  sizeof(a64_sysreg_table[0]));
}

const char *a64_sysreg_name_at(int index)
{
    if (index < 0 || index >= a64_sysreg_count())
        return NULL;
    return a64_sysreg_table[index].name;
}
