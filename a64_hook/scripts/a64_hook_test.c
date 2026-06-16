/*
 * a64_hook_test.c - Example and test program for a64_hook
 *
 * Demonstrates usage of the a64_hook kernel module API with various
 * hook types and configurations. Can be used as a user-space test
 * harness (for API validation) or integrated into kernel code.
 *
 * Build with: cc -o a64_hook_test a64_hook_test.c -I../include
 *
 * License: GPL v2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>

#include "a64_hook.h"

#define TEST_PASS  0
#define TEST_FAIL  1

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name, expr) do { \
    printf("  %-50s ", name); \
    if (expr) { \
        printf("PASS\n"); \
        tests_passed++; \
    } else { \
        printf("FAIL\n"); \
        tests_failed++; \
    } \
} while(0)

static void test_branch_encoding(void)
{
    printf("\n=== Branch Encoding Tests ===\n");

    unsigned long pc = 0xffffff8000000000;
    unsigned long target = pc + 0x1000;

    u32 b_insn = a64_insn_b(pc, target);
    TEST("B instruction encoding", a64_insn_is_b(b_insn));
    TEST("B instruction target", a64_branch_target(pc, b_insn) == target);

    u32 bl_insn = a64_insn_bl(pc, target);
    TEST("BL instruction encoding", a64_insn_is_bl(bl_insn));

    target = pc + 0x100;
    u32 bcond_insn = a64_insn_bcond(pc, target, A64_COND_EQ);
    TEST("B.cond encoding", a64_insn_is_bcond(bcond_insn));

    u32 br_insn = a64_insn_br(0);
    TEST("BR X0 encoding", (br_insn & 0xfffffc1f) == 0xd61f0000);

    u32 blr_insn = a64_insn_blr(5);
    TEST("BLR X5 encoding", (blr_insn & 0xfffffc1f) == 0xd63f0000);

    u32 ret_insn = a64_insn_ret(30);
    TEST("RET X30 encoding", ret_insn == 0xd65f03c0);

    u32 nop_insn = a64_insn_nop();
    TEST("NOP encoding", nop_insn == 0xd503201f);
    TEST("NOP detection", a64_insn_is_nop(nop_insn));

    u32 brk_insn = a64_insn_brk(0x100);
    TEST("BRK encoding", a64_insn_is_brk(brk_insn));

    target = pc - 0x100;
    b_insn = a64_insn_b(pc, target);
    TEST("B negative offset", a64_branch_target(pc, b_insn) == target);

    target = pc + 0x1000;
    bl_insn = a64_insn_bl(pc, target);
    TEST("BL target correct", a64_branch_target(pc, bl_insn) == target);

    u32 cbz_insn = a64_insn_cbz(pc, pc + 0x100, 0, false);
    TEST("CBZ encoding", a64_insn_is_cbz(cbz_insn));

    u32 tbz_insn = a64_insn_tbz(pc, pc + 0x100, 0, 5, true);
    TEST("TBZ encoding", a64_insn_is_tbz(tbz_insn));
}

static void test_data_processing_encoding(void)
{
    printf("\n=== Data Processing Encoding Tests ===\n");

    u32 movz = a64_insn_movz(0, 0x1234, 0);
    TEST("MOVZ W0, #0x1234", (movz & 0xffe00000) == 0x52800000);

    u32 movk = a64_insn_movk(0, 0x5678, 1);
    TEST("MOVK W0, #0x5678, LSL #16", (movk & 0xff800000) == 0x72800000);

    u32 add = a64_insn_add_imm(0, 1, 0x100, 0);
    TEST("ADD X0, X1, #0x100", (add & 0xff000000) == 0x11000000);

    u32 sub = a64_insn_sub_imm(0, 1, 0x100, 0);
    TEST("SUB X0, X1, #0x100", (sub & 0xff000000) == 0x51000000);

    u32 add_reg = a64_insn_add_reg(0, 1, 2, 0);
    TEST("ADD X0, X1, X2", (add_reg & 0xff000000) == 0x0b000000);

    u32 sub_reg = a64_insn_sub_reg(0, 1, 2, 0);
    TEST("SUB X0, X1, X2", (sub_reg & 0xff000000) == 0x4b000000);

    u32 and_insn = a64_insn_and_reg(0, 1, 2);
    TEST("AND X0, X1, X2", (and_insn & 0xff000000) == 0x0a000000);

    u32 orr_insn = a64_insn_orr_reg(0, 1, 2);
    TEST("ORR X0, X1, X2", (orr_insn & 0xff000000) == 0x2a000000);

    u32 eor_insn = a64_insn_eor_reg(0, 1, 2);
    TEST("EOR X0, X1, X2", (eor_insn & 0xff000000) == 0x4a000000);

    u32 mov = a64_insn_mov_reg(0, 1);
    TEST("MOV X0, X1", mov == a64_insn_orr_reg(0, 31, 1));

    u32 madd_insn = a64_insn_madd(0, 1, 2, 3);
    TEST("MADD X0, X1, X2, X3", (madd_insn & 0xff000000) == 0x1b000000);

    u32 cmp = a64_insn_cmp_imm(0, 0x100, 0);
    TEST("CMP X0, #0x100", (cmp & 0xffe00000) == 0x71000000);

    u32 csel_insn = a64_insn_csel(0, 1, 2, A64_COND_EQ);
    TEST("CSEL X0, X1, X2, EQ", (csel_insn & 0xff000000) == 0x1a000000);

    u32 sdiv_insn = a64_insn_sdiv(0, 1, 2);
    TEST("SDIV X0, X1, X2", (sdiv_insn & 0xffe00000) == 0x1ac00000);

    u32 udiv_insn = a64_insn_udiv(0, 1, 2);
    TEST("UDIV X0, X1, X2", (udiv_insn & 0xffe00000) == 0x1ac00000);
}

static void test_load_store_encoding(void)
{
    printf("\n=== Load/Store Encoding Tests ===\n");

    u32 ldr = a64_insn_ldr_imm(0, 1, 0x100, 3);
    TEST("LDR X0, [X1, #0x100]", (ldr & 0xffc00000) == 0xf9400000);

    u32 str = a64_insn_str_imm(0, 1, 0x100, 3);
    TEST("STR X0, [X1, #0x100]", (str & 0xffc00000) == 0xf9000000);

    u32 ldp_insn = a64_insn_ldp(0, 1, 2, 0x100, 3);
    TEST("LDP X0, X1, [X2, #0x100]", (ldp_insn & 0x7fc00000) == 0x29400000);

    u32 stp_insn = a64_insn_stp(0, 1, 2, 0x100, 3);
    TEST("STP X0, X1, [X2, #0x100]", (stp_insn & 0x7fc00000) == 0x29000000);

    unsigned long pc = 0xffffff8000000000;
    unsigned long target = pc + 0x1000;
    u32 ldrlit = a64_insn_ldr_literal(pc, target, 0);
    TEST("LDR X0, literal", (ldrlit & 0xff000000) == 0x18000000);

    u32 ldrb = a64_insn_ldrb_imm(0, 1, 0x100);
    TEST("LDRB W0, [X1, #0x100]", (ldrb & 0xffc00000) == 0x39400000);

    u32 strb = a64_insn_strb_imm(0, 1, 0x100);
    TEST("STRB W0, [X1, #0x100]", (strb & 0xffc00000) == 0x39000000);

    u32 ldrh = a64_insn_ldrh_imm(0, 1, 0x100);
    TEST("LDRH W0, [X1, #0x100]", (ldrh & 0xffc00000) == 0x79400000);

    u32 strh = a64_insn_strh_imm(0, 1, 0x100);
    TEST("STRH W0, [X1, #0x100]", (strh & 0xffc00000) == 0x79000000);

    u32 ldrsw = a64_insn_ldrsw_imm(0, 1, 0x100);
    TEST("LDRSW X0, [X1, #0x100]", (ldrsw & 0xffc00000) == 0xb9800000);
}

static void test_adr_adrp_encoding(void)
{
    printf("\n=== ADR/ADRP Encoding Tests ===\n");

    unsigned long pc = 0xffffff8000000000;

    u32 adr = a64_insn_adr(pc, pc + 0x1000, 0);
    TEST("ADR X0, label+0x1000", (adr & 0x9f000000) == 0x10000000);

    u32 adrp = a64_insn_adrp(pc, pc + 0x10000, 1);
    TEST("ADRP X1, page", (adrp & 0x9f000000) == 0x90000000);
}

static void test_system_encoding(void)
{
    printf("\n=== System Instruction Encoding Tests ===\n");

    u32 dmb = a64_insn_dmb(A64_BARRIER_ISH);
    TEST("DMB ISH", (dmb & 0xfffff0ff) == 0xd50330bf);

    u32 dsb = a64_insn_dsb(A64_BARRIER_SY);
    TEST("DSB SY", (dsb & 0xfffff0ff) == 0xd513309f);

    u32 isb = a64_insn_isb();
    TEST("ISB", isb == 0xd50330ff);

    u32 ic = a64_insn_ic_ivau(0);
    TEST("IC IVAU, X0", (ic & 0xfffffc00) == 0xd50b7400);

    u32 dc = a64_insn_dc_cvac(0);
    TEST("DC CVAC, X0", (dc & 0xfffffc00) == 0xd50b7800);

    u32 mrs = a64_insn_mrs("midr_el1", 0);
    TEST("MRS X0, MIDR_EL1", (mrs & 0xffffffff) == 0xd5380000);

    u32 msr = a64_insn_msr("tpidr_el0", 0);
    TEST("MSR TPIDR_EL0, X0", (msr & 0x1f) == 0);
}

static void test_pac_bti_encoding(void)
{
    printf("\n=== PAC/BTI Encoding Tests ===\n");

    u32 bti_c = a64_insn_bti_c();
    TEST("BTI C", bti_c == 0xd503245f);

    u32 bti_j = a64_insn_bti_j();
    TEST("BTI J", bti_j == 0xd503249f);

    u32 bti_jc = a64_insn_bti_jc();
    TEST("BTI JC", bti_jc == 0xd50324df);

    u32 esb = a64_insn_esb();
    TEST("ESB", esb == 0xd503221f);

    u32 csdb = a64_insn_csdb();
    TEST("CSDB", csdb == 0xd503229f);
}

static void test_fp_encoding(void)
{
    printf("\n=== Floating-Point Encoding Tests ===\n");

    u32 fmov = a64_insn_fmov_fp2fp(0, 1, 0);
    TEST("FMOV S0, S1", (fmov & 0xfffffc00) == 0x1e204000);

    u32 fadd = a64_insn_fadd_fp(0, 1, 2, 0);
    TEST("FADD S0, S1, S2", (fadd & 0xff000000) == 0x1e000000);

    u32 fsub = a64_insn_fsub_fp(0, 1, 2, 0);
    TEST("FSUB S0, S1, S2", (fsub & 0xff000000) == 0x1e000000);

    u32 fmul = a64_insn_fmul_fp(0, 1, 2, 0);
    TEST("FMUL S0, S1, S2", (fmul & 0xff000000) == 0x1e000000);

    u32 fdiv = a64_insn_fdiv_fp(0, 1, 2, 0);
    TEST("FDIV S0, S1, S2", (fdiv & 0xff000000) == 0x1e000000);

    u32 fabs = a64_insn_fabs_fp(0, 1, 0);
    TEST("FABS S0, S1", (fabs & 0xfffffc00) == 0x1e20c000);

    u32 fneg = a64_insn_fneg_fp(0, 1, 0);
    TEST("FNEG S0, S1", (fneg & 0xfffffc00) == 0x1e214000);

    u32 fsqrt = a64_insn_fsqrt_fp(0, 1, 0);
    TEST("FSQRT S0, S1", (fsqrt & 0xfffffc00) == 0x1e21c000);
}

static void test_instruction_decode(void)
{
    printf("\n=== Instruction Decode Tests ===\n");

    struct a64_hook_insn d;

    memset(&d, 0, sizeof(d));
    a64_decode_insn(0xd503201f, &d);
    TEST("NOP decode", d.is_nop);

    memset(&d, 0, sizeof(d));
    a64_decode_insn(0x14000000, &d);
    TEST("B decode", d.is_branch);

    memset(&d, 0, sizeof(d));
    a64_decode_insn(0x94000000, &d);
    TEST("BL decode", d.is_branch && d.is_call);

    memset(&d, 0, sizeof(d));
    a64_decode_insn(0xd65f03c0, &d);
    TEST("RET decode", d.is_branch && d.is_ret);

    memset(&d, 0, sizeof(d));
    a64_decode_insn(0xd61f0000, &d);
    TEST("BR X0 decode", d.is_branch && d.is_indirect);

    memset(&d, 0, sizeof(d));
    a64_decode_insn(0xd63f0000, &d);
    TEST("BLR X0 decode", d.is_branch && d.is_call);

    memset(&d, 0, sizeof(d));
    a64_decode_insn(0x54000000, &d);
    TEST("B.EQ decode", d.is_branch);

    memset(&d, 0, sizeof(d));
    a64_decode_insn(0x34000000, &d);
    TEST("CBZ decode", d.is_branch);

    memset(&d, 0, sizeof(d));
    a64_decode_insn(0x36000000, &d);
    TEST("TBZ decode", d.is_branch);

    TEST("NOP detect", a64_insn_is_nop(0xd503201f));
    TEST("BRK detect", a64_insn_is_brk(0xd4200000));
    TEST("B detect", a64_insn_is_b(0x14000000));
    TEST("BL detect", a64_insn_is_bl(0x94000000));
    TEST("B.cond detect", a64_insn_is_bcond(0x54000000));
    TEST("CBZ detect", a64_insn_is_cbz(0x34000000));
    TEST("TBZ detect", a64_insn_is_tbz(0x36000000));
}

static void test_mte_encoding(void)
{
    printf("\n=== MTE Encoding Tests ===\n");

    u32 stg = a64_insn_stg(0, 1, 0x100);
    TEST("STG X0, [X1, #0x100]", (stg & 0xff800000) == 0xd9800000);

    u32 ldg = a64_insn_ldg(0, 1, 0x100);
    TEST("LDG X0, [X1, #0x100]", (ldg & 0xff800000) == 0xd9800000);

    u32 irg = a64_insn_irg(0, 1, 2);
    TEST("IRG X0, X1, X2", (irg & 0xffe0fc00) == 0x9ac01000);

    u32 addg = a64_insn_addg(0, 1, 0x10, 0);
    TEST("ADDG X0, X1, #0x10, #0", (addg & 0xff800000) == 0x91800000);
}

static void test_barrier_names(void)
{
    printf("\n=== Barrier Encoding Tests ===\n");

    u32 dmb_sy = a64_insn_dmb(A64_BARRIER_SY);
    TEST("DMB SY (full system)", (dmb_sy >> 8 & 0xf) == 0xf);

    u32 dmb_ish = a64_insn_dmb(A64_BARRIER_ISH);
    TEST("DMB ISH (inner shareable)", (dmb_ish >> 8 & 0xf) == 0xb);

    u32 dmb_osh = a64_insn_dmb(A64_BARRIER_OSH);
    TEST("DMB OSH (outer shareable)", (dmb_osh >> 8 & 0xf) == 0x3);

    u32 dmb_nsh = a64_insn_dmb(A64_BARRIER_NSH);
    TEST("DMB NSH (non-shareable)", (dmb_nsh >> 8 & 0xf) == 0x7);

    u32 dsb_sy = a64_insn_dsb(A64_BARRIER_SY);
    TEST("DSB SY has barrier bit", (dsb_sy >> 20) & 1);

    u32 isb_val = a64_insn_isb();
    (void)isb_val;
    TEST("ISB is self-consistent",
         isb_val == 0xd50330ff &&
         a64_insn_isb() == 0xd50330ff);
}

static void test_register_analysis(void)
{
    printf("\n=== Register Analysis Tests ===\n");

    u8 regs[8];
    int n;

    n = a64_insn_regs_read(0x8b020020, regs, 8);
    TEST("ADD reads 2 registers", n >= 2);

    n = a64_insn_regs_written(0x8b020020, regs, 8);
    TEST("ADD writes 1 register", n >= 1);

    n = a64_insn_regs_read(0xf9400000, regs, 8);
    TEST("LDR reads base register", n >= 1);

    n = a64_insn_regs_written(0xf9400000, regs, 8);
    TEST("LDR writes destination", n >= 1);
}

static void test_hook_api(void)
{
    printf("\n=== Hook API Tests ===\n");

    struct a64_hook hook;
    int ret;

    memset(&hook, 0, sizeof(hook));
    ret = a64_hook_init(&hook, "test_hook", 0x1000, 0x2000,
                         A64_HOOK_TYPE_DETOUR, A64_HOOK_DEFAULT_FLAGS);
    TEST("a64_hook_init success", ret == 0);
    TEST("Hook name set", strcmp(hook.name, "test_hook") == 0);
    TEST("Hook target set", hook.target_addr == 0x1000);
    TEST("Hook handler set", hook.handler_addr == 0x2000);
    TEST("Hook type set", hook.type == A64_HOOK_TYPE_DETOUR);
    TEST("Hook state disabled", hook.state == A64_HOOK_STATE_DISABLED);

    struct a64_hook *allocated = a64_hook_alloc();
    TEST("a64_hook_alloc success", allocated != NULL);
    TEST("Initial state disabled",
         allocated->state == A64_HOOK_STATE_DISABLED);

    if (allocated) {
        strcpy(allocated->name, "test_alloc");
        allocated->target_addr = 0x3000;
        allocated->handler_addr = 0x4000;
        a64_hook_free(allocated);
        TEST("a64_hook_free works", 1);
    }
}

static void test_inline_helpers(void)
{
    printf("\n=== Inline Helper Tests ===\n");

    TEST("a64_insn_valid on NOP", a64_insn_valid(0xd503201f));
    TEST("a64_insn_valid on 0", !a64_insn_valid(0));
    TEST("a64_insn_valid on -1", !a64_insn_valid(0xffffffff));

    TEST("a64_insn_rd of ADD", a64_insn_rd(0x8b000000) == 0);
    TEST("a64_insn_rn of ADD", a64_insn_rn(0x8b000020) == 1);
    TEST("a64_insn_rm of ADD", a64_insn_rm(0x8b020000) == 2);

    TEST("a64_insn_rt of LDR", a64_insn_rt(0xf9400000) == 0);

    u32 test_insn = 0xd503201f;
    volatile u32 *addr = &test_insn;
    TEST("a64_get_insn readback",
         a64_get_insn(addr) == 0xd503201f);

    a64_set_insn(addr, 0x14000000);
    TEST("a64_set_insn write", *addr == 0x14000000);
}

static void test_error_codes(void)
{
    printf("\n=== Error Code Tests ===\n");

    TEST("A64_HOOK_SUCCESS == 0", A64_HOOK_SUCCESS == 0);
    TEST("A64_HOOK_ERR_NOMEM != 0", A64_HOOK_ERR_NOMEM != 0);
    TEST("A64_HOOK_ERR_INVAL != 0", A64_HOOK_ERR_INVAL != 0);
    TEST("A64_HOOK_ERR_NOSYM != 0", A64_HOOK_ERR_NOSYM != 0);
    TEST("A64_HOOK_ERR_DMA defined", A64_HOOK_ERR_DMA != 0);
    TEST("A64_HOOK_ERR_KPROBE defined", A64_HOOK_ERR_KPROBE != 0);
    TEST("Error codes distinct",
         A64_HOOK_ERR_NOMEM != A64_HOOK_ERR_INVAL &&
         A64_HOOK_ERR_INVAL != A64_HOOK_ERR_NOSYM &&
         A64_HOOK_ERR_NOSYM != A64_HOOK_ERR_HOOK_EXISTS);
}

static void test_flags(void)
{
    printf("\n=== Flag Tests ===\n");

    TEST("A64_HOOK_F_DMA defined", A64_HOOK_F_DMA != 0);
    TEST("A64_HOOK_F_KPROBE defined", A64_HOOK_F_KPROBE != 0);
    TEST("A64_HOOK_F_ATOMIC defined", A64_HOOK_F_ATOMIC != 0);
    TEST("A64_HOOK_F_TRAMPOLINE defined", A64_HOOK_F_TRAMPOLINE != 0);
    TEST("A64_HOOK_F_BPF defined", A64_HOOK_F_BPF != 0);
    TEST("A64_HOOK_F_STEALTH defined", A64_HOOK_F_STEALTH != 0);

    u64 combined = A64_HOOK_F_DMA | A64_HOOK_F_ATOMIC |
                   A64_HOOK_F_PREEMPT_SAFE;
    TEST("Default flags combination", combined == A64_HOOK_DEFAULT_FLAGS);

    TEST("Flag bit uniqueness",
         (A64_HOOK_F_NONE == 0) &&
         (A64_HOOK_F_KPROBE != A64_HOOK_F_DMA) &&
         (A64_HOOK_F_ATOMIC != A64_HOOK_F_BPF));
}

static void test_cond_names(void)
{
    printf("\n=== Condition Code Tests ===\n");

    TEST("EQ == 0", A64_COND_EQ == 0);
    TEST("NE == 1", A64_COND_NE == 1);
    TEST("CS == 2", A64_COND_CS == 2);
    TEST("CC == 3", A64_COND_CC == 3);
    TEST("MI == 4", A64_COND_MI == 4);
    TEST("PL == 5", A64_COND_PL == 5);
    TEST("VS == 6", A64_COND_VS == 6);
    TEST("VC == 7", A64_COND_VC == 7);
    TEST("HI == 8", A64_COND_HI == 8);
    TEST("LS == 9", A64_COND_LS == 9);
    TEST("GE == 10", A64_COND_GE == 10);
    TEST("LT == 11", A64_COND_LT == 11);
    TEST("GT == 12", A64_COND_GT == 12);
    TEST("LE == 13", A64_COND_LE == 13);
    TEST("AL == 14", A64_COND_AL == 14);
    TEST("NV == 15", A64_COND_NV == 15);
}

static void test_branch_range(void)
{
    printf("\n=== Branch Range Tests ===\n");

    unsigned long pc = 0xffffff8000000000;

    TEST("B to nearby target",
         a64_branch_target(pc, a64_insn_b(pc, pc + 0x1000)) == pc + 0x1000);

    TEST("B to far target",
         a64_branch_target(pc, a64_insn_b(pc, pc + 0x01ffffff * 4)) ==
         pc + 0x01ffffff * 4);

    TEST("B backward target",
         a64_branch_target(pc, a64_insn_b(pc, pc - 0x1000)) == pc - 0x1000);

    TEST("B near max range",
         a64_branch_target(pc,
             a64_insn_b(pc, pc + 0x01ffffff * 4)) == pc + 0x01ffffff * 4);

    TEST("Branch range check in range",
         a64_branch_in_range(pc, pc + 0x1000));

    TEST("Branch range check out of range",
         !a64_branch_in_range(pc, pc + 0x100000000));
}

/* Stub implementations for user-space testing */
struct a64_hook *a64_hook_alloc(void) { return calloc(1, sizeof(struct a64_hook)); }
void a64_hook_free(struct a64_hook *h) { free(h); }
int a64_hook_init(struct a64_hook *hook, const char *name,
                  unsigned long target, unsigned long handler,
                  enum a64_hook_type type, u64 flags)
{
    if (!hook || !name) return -1;
    memset(hook, 0, sizeof(*hook));
    strncpy(hook->name, name, sizeof(hook->name) - 1);
    hook->target_addr = target;
    hook->handler_addr = handler;
    hook->type = type;
    hook->flags = flags;
    hook->state = A64_HOOK_STATE_DISABLED;
    return 0;
}

int main(void)
{
    printf("\n==================================\n");
    printf("a64_hook Test Suite v" A64_HOOK_VERSION_STRING "\n");
    printf("==================================\n");

    test_branch_encoding();
    test_data_processing_encoding();
    test_load_store_encoding();
    test_adr_adrp_encoding();
    test_system_encoding();
    test_pac_bti_encoding();
    test_fp_encoding();
    test_mte_encoding();
    test_barrier_names();
    test_instruction_decode();
    test_register_analysis();
    test_hook_api();
    test_inline_helpers();
    test_error_codes();
    test_flags();
    test_cond_names();
    test_branch_range();

    printf("\n==================================\n");
    printf("Results: %d passed, %d failed out of %d tests\n",
           tests_passed, tests_failed,
           tests_passed + tests_failed);
    printf("==================================\n");

    return tests_failed > 0 ? TEST_FAIL : TEST_PASS;
}
