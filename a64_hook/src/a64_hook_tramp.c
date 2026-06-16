#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/set_memory.h>
#include <asm/cacheflush.h>

#include "a64_hook.h"
#include "a64_hook_sym.h"

int a64_tramp_alloc(struct a64_trampoline *tramp, int n_slots)
{
    size_t size;
    int ret;

    if (!tramp || n_slots <= 0)
        return -EINVAL;

    size = PAGE_ALIGN((n_slots + A64_HOOK_MAX_INSN_SIZE) * A64_INSN_SIZE * 8);

    if (!a64_sym.module_alloc) {
        pr_err("a64_hook: module_alloc not available\n");
        return -ENOSYS;
    }

    tramp->code = a64_sym.module_alloc(size);
    if (!tramp->code)
        return -ENOMEM;

    tramp->size = size;
    tramp->allocated = true;
    tramp->in_use = false;
    tramp->n_insns = 0;
    spin_lock_init(&tramp->lock);

    memset(tramp->code, 0, size);

    if (a64_sym.set_memory_x) {
        ret = a64_sym.set_memory_x((unsigned long)tramp->code,
                                    size >> PAGE_SHIFT);
        if (ret < 0) {
            pr_err("a64_hook: set_memory_x failed: %d\n", ret);
            a64_sym.vfree(tramp->code);
            tramp->code = NULL;
            tramp->allocated = false;
            return ret;
        }
    }

    a64_hook_stats.total_trampolines++;

    return 0;
}

void a64_tramp_free(struct a64_trampoline *tramp)
{
    if (!tramp || !tramp->code)
        return;

    if (tramp->allocated && a64_sym.vfree)
        a64_sym.vfree(tramp->code);

    tramp->code = NULL;
    tramp->allocated = false;
    tramp->in_use = false;
    tramp->size = 0;
    tramp->n_insns = 0;
}

static int a64_tramp_emit_save_regs(struct a64_trampoline *tramp, u32 reg_mask,
                                    int start)
{
    int i, pos = start;
    u8 regs[32];
    int n_regs = 0;

    for (i = 0; i < 32; i++) {
        if (reg_mask & (1U << i))
            regs[n_regs++] = i;
    }

    if (n_regs == 0)
        return start;

    if (n_regs <= 2) {
        if (n_regs >= 1)
            tramp->code[pos++] = a64_insn_str_imm(regs[0], 31, -8, 3);
        if (n_regs >= 2)
            tramp->code[pos++] = a64_insn_str_imm(regs[1], 31, -16, 3);
    } else {
        int stack_size = ALIGN(n_regs * 8, 16);
        tramp->code[pos++] = a64_insn_sub_imm(31, 31, stack_size, 0);
        for (i = 0; i < n_regs; i++)
            tramp->code[pos++] = a64_insn_str_imm(regs[i], 31,
                                                   i * 8, 3);
    }

    tramp->reg_save_mask = reg_mask;
    return pos;
}

static int a64_tramp_emit_restore_regs(struct a64_trampoline *tramp,
                                        u32 reg_mask, int start)
{
    int i, pos = start;
    u8 regs[32];
    int n_regs = 0;

    for (i = 0; i < 32; i++) {
        if (reg_mask & (1U << i))
            regs[n_regs++] = i;
    }

    if (n_regs == 0)
        return start;

    if (n_regs <= 2) {
        if (n_regs >= 1)
            tramp->code[pos++] = a64_insn_ldr_imm(regs[0], 31, -8, 3);
        if (n_regs >= 2)
            tramp->code[pos++] = a64_insn_ldr_imm(regs[1], 31, -16, 3);
    } else {
        int stack_size = ALIGN(n_regs * 8, 16);
        for (i = 0; i < n_regs; i++)
            tramp->code[pos++] = a64_insn_ldr_imm(regs[i], 31,
                                                   i * 8, 3);
        tramp->code[pos++] = a64_insn_add_imm(31, 31, stack_size, 0);
    }

    tramp->reg_restore_mask = reg_mask;
    return pos;
}

int a64_tramp_generate(struct a64_trampoline *tramp,
                        const struct a64_hook_insn *insns, int n_insns,
                        unsigned long handler_addr, unsigned long priv,
                        unsigned long return_addr)
{
    int pos = 0;
    int i;
    unsigned long code_addr;

    if (!tramp || !insns || n_insns <= 0)
        return -EINVAL;

    if (!tramp->code) {
        int ret = a64_tramp_alloc(tramp, n_insns + 32);
        if (ret < 0)
            return ret;
    }

    code_addr = (unsigned long)tramp->code;

    pos = a64_tramp_emit_save_regs(tramp, A64_TRAMP_SAVE_CALLER | A64_TRAMP_SAVE_X30, pos);

    tramp->code[pos++] = a64_insn_movz(0, 0, 0);

    tramp->code[pos++] = a64_insn_movz(1, priv & 0xffff, 0);
    tramp->code[pos++] = a64_insn_movk(1, (priv >> 16) & 0xffff, 1);
    tramp->code[pos++] = a64_insn_movk(1, (priv >> 32) & 0xffff, 2);
    tramp->code[pos++] = a64_insn_movk(1, (priv >> 48) & 0xffff, 3);

    if (a64_branch_in_range(code_addr + pos * 4, handler_addr)) {
        tramp->code[pos++] = a64_insn_adr(code_addr + pos * 4, handler_addr, 16);
    } else {
        tramp->code[pos++] = a64_insn_adrp(code_addr + pos * 4, handler_addr, 16);
        tramp->code[pos++] = a64_insn_add_imm(16, 16, handler_addr & 0xfff, 0);
    }

    tramp->code[pos++] = a64_insn_blr(16);

    pos = a64_tramp_emit_restore_regs(tramp, A64_TRAMP_SAVE_CALLER | A64_TRAMP_SAVE_X30, pos);

    for (i = 0; i < n_insns; i++) {
        tramp->code[pos++] = insns[i].insn;
    }

    {
        unsigned long branch_pc = code_addr + pos * 4;
        tramp->code[pos++] = a64_insn_b(branch_pc, return_addr);
    }

    tramp->pc = (unsigned long)tramp->code;
    tramp->n_insns = pos;
    tramp->n_saved = n_insns;
    memcpy(tramp->saved_insns, insns,
           n_insns * sizeof(struct a64_hook_insn));

    a64_dma_flush_icache((unsigned long)tramp->code,
                          pos * A64_INSN_SIZE);

    pr_info("a64_hook: trampoline at 0x%lx, %d insns, priv=0x%lx, handler=0x%lx, return=0x%lx\n",
            code_addr, pos, priv, handler_addr, return_addr);
    {
        int di;
        for (di = 0; di < pos; di++)
            pr_info("a64_hook: tramp[%3d]  pc=0x%lx  insn=0x%08x\n",
                    di, code_addr + di * 4, tramp->code[di]);
    }

    return pos;
}

int a64_tramp_install(struct a64_trampoline *tramp, unsigned long at)
{
    if (!tramp || !tramp->code || !at)
        return -EINVAL;

    tramp->pc = at;
    tramp->in_use = true;

    return 0;
}

void a64_tramp_remove(struct a64_trampoline *tramp)
{
    if (!tramp)
        return;

    tramp->in_use = false;
}

unsigned long a64_tramp_entry(struct a64_trampoline *tramp)
{
    if (!tramp || !tramp->code)
        return 0;

    return tramp->pc ? tramp->pc : (unsigned long)tramp->code;
}
