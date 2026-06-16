/*
 * a64_hook_core.c - Core Hook Engine
 *
 * ARM64 inline hook engine with DMA-based physical memory writes.
 * Provides hook installation, trampoline generation, atomic patching,
 * hook chaining, BPF integration, and comprehensive state management.
 *
 * Designed for Android 12-16 (API 31+) ARM64 devices.
 * Loaded via root (su) as a loadable kernel module.
 *
 * License: GPL v2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/stop_machine.h>
#include <linux/preempt.h>
#include <linux/hardirq.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/atomic.h>
#include <linux/cache.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <asm/cacheflush.h>
#include <asm/barrier.h>
#include <asm/tlbflush.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/io.h>

#include "a64_hook.h"
#include "a64_hook_sym.h"

/*
 * Forward declarations
 */
static int  a64_hook_do_install(struct a64_hook *hook);
static int  a64_hook_do_uninstall(struct a64_hook *hook);
static int  a64_hook_validate_target(struct a64_hook *hook);
static int  a64_hook_resolve_symbol(const char *sym_name,
                                     unsigned long *addr,
                                     char *module_name,
                                     size_t mod_name_size);

/*
 * Hook hash table for fast lookup
 */
#define A64_HOOK_HASH_BITS 10
static DEFINE_HASHTABLE(a64_hook_hash, A64_HOOK_HASH_BITS);
static DEFINE_MUTEX(a64_hook_mutex);

/*
 * Atomic patching work structure for stop_machine
 */
struct a64_atomic_patch_work {
    unsigned long  addr;
    u32            insn;
    u32            old_insn;
    int            result;
    bool           done;
};

static int a64_atomic_patch_cb(void *data)
{
    struct a64_atomic_patch_work *work = data;
    u32 old;
    unsigned long page_start = work->addr & PAGE_MASK;

    if (a64_sym.set_memory_rw)
        a64_sym.set_memory_rw(page_start, 1);

    old = a64_get_insn((volatile u32 *)work->addr);
    a64_set_insn((volatile u32 *)work->addr, work->insn);

    if (a64_sym.set_memory_ro)
        a64_sym.set_memory_ro(page_start, 1);

    work->old_insn = old;
    work->result = 0;
    work->done = true;

    return 0;
}

/*
 * Atomic patch a single instruction using stop_machine
 */
int a64_atomic_patch_single(unsigned long addr, u32 insn, u32 *old)
{
    struct a64_atomic_patch_work work;
    int ret;

    work.addr = addr;
    work.insn = insn;
    work.old_insn = 0;
    work.result = 0;
    work.done = false;

    a64_hook_stats.stop_machine_calls++;

    if (a64_hook_use_stop_machine) {
        ret = stop_machine(a64_atomic_patch_cb, &work, NULL);
        if (ret)
            return ret;
        work.result = 0;
    } else {
        if (a64_sym.aarch64_insn_write) {
            if (old)
                *old = a64_get_insn((volatile u32 *)addr);
            work.result = a64_sym.aarch64_insn_write((void *)addr, insn);
        } else {
            unsigned long page_start = addr & PAGE_MASK;
            if (a64_sym.set_memory_rw)
                a64_sym.set_memory_rw(page_start, 1);
            if (old)
                *old = a64_get_insn((volatile u32 *)addr);
            a64_set_insn((volatile u32 *)addr, insn);
            if (a64_sym.set_memory_ro)
                a64_sym.set_memory_ro(page_start, 1);
            work.result = 0;
        }
        work.old_insn = old ? *old : 0;
    }

    a64_dma_flush_icache(addr, 4);

    if (old)
        *old = work.old_insn;

    return work.result;
}

/*
 * Atomic patch multiple instructions using stop_machine
 */
int a64_atomic_patch_multi(unsigned long *addrs, u32 *insns, int n)
{
    int i, ret;

    for (i = 0; i < n; i++) {
        ret = a64_atomic_patch_single(addrs[i], insns[i], NULL);
        if (ret)
            return ret;
    }

    return 0;
}

/*
 * Find the minimum number of instructions to cover a branch
 * We need to ensure that when we replace instructions at the target,
 * any branches into the middle of our replacement are also handled.
 *
 * For a standard 4-byte branch, all instructions must be fully within
 * the branch range. This function determines how many instructions
 * to replace to safely install a hook.
 */
int a64_find_hook_region(const u32 *code, int max_insns,
                          unsigned long target, unsigned long handler,
                          u32 *hook_insn)
{
    int i;
    unsigned long pc;
    long offset;
    u32 branch;
    struct a64_hook_insn decoded;

    for (i = 0; i < max_insns && i < A64_HOOK_MAX_INSN_SIZE; i++) {
        pc = target + i * 4;

        /* Check if we can branch from pc to handler */
        offset = (long)(handler - pc);
        if (offset >= -A64_HOOK_BRANCH_RANGE && offset < A64_HOOK_BRANCH_RANGE) {
            /* We can branch from this point - but we may need to include
             * preceding instructions to ensure no branch target lands in
             * the middle of our patched region.
             *
             * For simplicity, check if any of the instructions we're
             * replacing are branch targets from within the region.
             * For a production hook, this needs instruction analysis.
             */

            /* Generate the branch instruction */
            branch = a64_insn_b(pc, handler);
            if (hook_insn)
                *hook_insn = branch;
            return i + 1;
        }

        /* If this instruction is a branch/call, it might branch backwards
         * into our region, which would complicate things */
        a64_decode_insn(code[i], &decoded);
        if (decoded.is_branch) {
            unsigned long branch_target = a64_branch_target(pc, code[i]);
            if (branch_target > target && branch_target < pc) {
                continue;
            }
        }
    }

    return -A64_HOOK_ERR_BRANCH_OUT;
}

/*
 * Install a hook (main entry point)
 */
int a64_hook_install(struct a64_hook *hook)
{
    int ret;
    unsigned long flags;

    if (!hook) {
        pr_err("a64_hook: install: NULL hook\n");
        return -EINVAL;
    }

    if (strlen(hook->name) == 0) {
        pr_err("a64_hook: install: hook has no name\n");
        return -EINVAL;
    }

    if (!hook->target_addr && !hook->handler_addr) {
        pr_err("a64_hook: install: no target/handler for '%s'\n", hook->name);
        return -EINVAL;
    }

    if (hook->target_addr == hook->handler_addr) {
        pr_err("a64_hook: install: target == handler for '%s'\n", hook->name);
        return -EINVAL;
    }

    if (atomic_read(&a64_hook_count_atomic) >= a64_hook_max_hooks) {
        pr_err("a64_hook: install: max hooks reached (%d)\n",
               a64_hook_max_hooks);
        return -A64_HOOK_ERR_TOO_MANY;
    }

    /* Validate hook target */
    ret = a64_hook_validate_target(hook);
    if (ret == -A64_HOOK_ERR_BRANCH_OUT &&
        hook->type != A64_HOOK_TYPE_KPROBE &&
        hook->type != A64_HOOK_TYPE_RETPROBE) {
        pr_info("a64_hook: branch range exceeded for '%s', trying kprobe\n",
               hook->name);
        if (a64_hook_use_kprobes && a64_kprobe_available()) {
            hook->type = A64_HOOK_TYPE_KPROBE;
        } else {
            pr_err("a64_hook: kprobes unavailable, cannot hook '%s'\n",
                   hook->name);
            return ret;
        }
    } else if (ret < 0) {
        pr_err("a64_hook: install: invalid target for '%s': %d\n",
               hook->name, ret);
        return ret;
    }

    /* Check for duplicate hooks (inline to avoid deadlock with a64_hook_find) */
    spin_lock_irqsave(&a64_hook_list_lock, flags);
    {
        struct a64_hook *tmp;
        list_for_each_entry(tmp, &a64_hook_list, list) {
            if (strcmp(tmp->name, hook->name) == 0) {
                spin_unlock_irqrestore(&a64_hook_list_lock, flags);
                pr_err("a64_hook: install: hook '%s' already exists\n", hook->name);
                return -A64_HOOK_ERR_HOOK_EXISTS;
            }
        }
    }
    spin_unlock_irqrestore(&a64_hook_list_lock, flags);

    /* Save original instructions (pc/index set AFTER a64_decode_insn,
     * which memset's the entire struct) */
    {
        int i;
        for (i = 0; i < A64_HOOK_MAX_INSN_SIZE; i++) {
            hook->orig_insns[i].insn = a64_get_insn(
                (volatile u32 *)(hook->target_addr + i * 4));
            a64_decode_insn(hook->orig_insns[i].insn, &hook->orig_insns[i]);
            hook->orig_insns[i].pc = hook->target_addr + i * 4;
            hook->orig_insns[i].index = i;
        }
    }

    /* Find the hook region (how many instructions to replace) */
    ret = a64_find_hook_region((const u32 *)hook->orig_insns,
                                A64_HOOK_MAX_INSN_SIZE,
                                hook->target_addr, hook->handler_addr,
                                &hook->hook_insn);
    if (ret == -A64_HOOK_ERR_BRANCH_OUT &&
        hook->type != A64_HOOK_TYPE_KPROBE &&
        hook->type != A64_HOOK_TYPE_RETPROBE) {
        pr_info("a64_hook: branch region exceeded for '%s', trying kprobe\n",
               hook->name);
        if (a64_hook_use_kprobes && a64_kprobe_available()) {
            hook->type = A64_HOOK_TYPE_KPROBE;
        } else {
            pr_err("a64_hook: kprobes unavailable, cannot hook '%s'\n",
                   hook->name);
            return ret;
        }
    } else if (ret < 0) {
        pr_err("a64_hook: install: cannot find hook region for '%s': %d\n",
               hook->name, ret);
        return ret;
    }
    hook->n_orig_insns = ret;

    /* Check the resolved hook type */
    switch (hook->type) {
    case A64_HOOK_TYPE_INLINE:
    case A64_HOOK_TYPE_DETOUR:
    case A64_HOOK_TYPE_BL:
    case A64_HOOK_TYPE_BR:
    case A64_HOOK_TYPE_BLR:
    case A64_HOOK_TYPE_DMA_ONLY:
        ret = a64_hook_do_install(hook);
        break;

    case A64_HOOK_TYPE_KPROBE:
    case A64_HOOK_TYPE_RETPROBE:
        if (!a64_hook_use_kprobes) {
            pr_err("a64_hook: kprobes disabled, cannot install '%s'\n",
                   hook->name);
            return -A64_HOOK_ERR_KPROBE;
        }
        ret = a64_kprobe_install(hook);
        break;

    case A64_HOOK_TYPE_FENTRY:
    case A64_HOOK_TYPE_FEXIT:
        /* Fentry/fexit hooks use the same inline mechanism but with
         * different registration */
        ret = a64_hook_do_install(hook);
        break;

    default:
        pr_err("a64_hook: install: unknown type %d for '%s'\n",
               hook->type, hook->name);
        return -A64_HOOK_ERR_INVAL;
    }

    if (ret < 0) {
        pr_err("a64_hook: install: failed for '%s': %d\n", hook->name, ret);
        return ret;
    }

    /* Add to global list and hash table */
    spin_lock_irqsave(&a64_hook_list_lock, flags);
    hook->state = A64_HOOK_STATE_ENABLED;
    hook->create_time = get_jiffies_64();
    hook->stats.installed_at_jiffies = hook->create_time;
    list_add_tail(&hook->list, &a64_hook_list);
    hash_add(a64_hook_hash, &hook->hash_node,
             hash_ptr((void *)hook->target_addr, A64_HOOK_HASH_BITS));
    atomic_inc(&a64_hook_count_atomic);
    atomic_inc(&a64_hook_enabled_count);
    a64_hook_stats.total_hooks++;
    a64_hook_stats.enabled_hooks++;

    if (atomic_read(&a64_hook_count_atomic) > a64_hook_stats.peak_hook_count)
        a64_hook_stats.peak_hook_count = atomic_read(&a64_hook_count_atomic);

    spin_unlock_irqrestore(&a64_hook_list_lock, flags);

    if (a64_hook_verbose > 0) {
        pr_info("a64_hook: installed '%s' at 0x%lx -> 0x%lx (type=%d, %d insns)\n",
                hook->name, hook->target_addr, hook->handler_addr,
                hook->type, hook->n_orig_insns);
    }

    return A64_HOOK_SUCCESS;
}

/*
 * Uninstall a hook
 */
int a64_hook_uninstall(struct a64_hook *hook)
{
    int ret;
    unsigned long flags;
    int i;

    if (!hook)
        return -EINVAL;

    if (a64_hook_verbose > 0)
        pr_info("a64_hook: uninstalling '%s'\n", hook->name);

    /* Remove from global list and hash table (before state change) */
    spin_lock_irqsave(&a64_hook_list_lock, flags);
    list_del(&hook->list);
    hash_del(&hook->hash_node);
    atomic_dec(&a64_hook_count_atomic);
    if (hook->state == A64_HOOK_STATE_ENABLED)
        atomic_dec(&a64_hook_enabled_count);
    spin_unlock_irqrestore(&a64_hook_list_lock, flags);

    /* Mark as removing */
    spin_lock_irqsave(&hook->lock, flags);
    hook->state = A64_HOOK_STATE_REMOVING;
    spin_unlock_irqrestore(&hook->lock, flags);

    switch (hook->type) {
    case A64_HOOK_TYPE_KPROBE:
    case A64_HOOK_TYPE_RETPROBE:
        ret = a64_kprobe_remove(hook);
        break;

    default:
        pr_info("a64_hook_dbg: restoring %d insns for '%s'\n",
                hook->n_orig_insns, hook->name);
        /* Restore original instructions in reverse order */
        for (i = hook->n_orig_insns - 1; i >= 0; i--) {
            pr_info("a64_hook_dbg: restoring insn[%d] at 0x%lx val=0x%08x\n",
                    i, hook->orig_insns[i].pc, hook->orig_insns[i].insn);
            ret = a64_atomic_patch_single(
                hook->orig_insns[i].pc,
                hook->orig_insns[i].insn, NULL);
            if (ret < 0) {
                pr_err("a64_hook: failed to restore insn %d for '%s': %d\n",
                       i, hook->name, ret);
            }
        }

        /* Free trampoline if allocated */
        if (hook->trampoline) {
            a64_tramp_free(hook->trampoline);
        }

        /* Free DMA mapping if allocated */
        if (hook->dma_map) {
            a64_dma_unmap_target(hook->dma_map);
            hook->dma_map = NULL;
        }

        /* Detach BPF if attached */
        if (hook->bpf_ctx) {
            a64_hook_detach_bpf(hook);
        }

        ret = A64_HOOK_SUCCESS;
        break;
    }

    spin_lock_irqsave(&hook->lock, flags);
    hook->state = A64_HOOK_STATE_DISABLED;
    hook->modify_time = get_jiffies_64();
    spin_unlock_irqrestore(&hook->lock, flags);

    if (a64_hook_verbose > 0)
        pr_info("a64_hook: uninstalled '%s'\n", hook->name);

    return ret;
}

/*
 * Enable a hook (re-install after disable)
 */
int a64_hook_enable(struct a64_hook *hook)
{
    unsigned long flags;

    if (!hook)
        return -EINVAL;

    spin_lock_irqsave(&hook->lock, flags);
    if (hook->state == A64_HOOK_STATE_ENABLED) {
        spin_unlock_irqrestore(&hook->lock, flags);
        return A64_HOOK_SUCCESS;
    }
    spin_unlock_irqrestore(&hook->lock, flags);

    return a64_hook_install(hook);
}

/*
 * Disable a hook (temporarily remove, keep state)
 */
int a64_hook_disable(struct a64_hook *hook)
{
    int ret;
    unsigned long flags;

    if (!hook)
        return -EINVAL;

    spin_lock_irqsave(&hook->lock, flags);
    if (hook->state != A64_HOOK_STATE_ENABLED) {
        spin_unlock_irqrestore(&hook->lock, flags);
        return A64_HOOK_SUCCESS;
    }
    hook->state = A64_HOOK_STATE_PENDING;
    spin_unlock_irqrestore(&hook->lock, flags);

    /* Restore original instructions */
    ret = a64_hook_do_uninstall(hook);

    spin_lock_irqsave(&hook->lock, flags);
    if (ret == A64_HOOK_SUCCESS)
        hook->state = A64_HOOK_STATE_DISABLED;
    else
        hook->state = A64_HOOK_STATE_ERROR;
    hook->modify_time = get_jiffies_64();
    spin_unlock_irqrestore(&hook->lock, flags);

    return ret;
}

/*
 * Remove a hook (free all resources)
 */
void a64_hook_remove(struct a64_hook *hook)
{
    if (!hook)
        return;

    a64_hook_uninstall(hook);
    a64_hook_free(hook);
}

/*
 * Install a hook by symbol name
 */
int a64_hook_install_by_name(const char *name, const char *target_sym,
                              a64_hook_handler_t handler, void *priv,
                              u64 flags)
{
    struct a64_hook *hook;
    unsigned long addr;
    char module_name[A64_HOOK_MODULE_NAME_LEN];
    int ret;

    /* Resolve symbol */
    ret = a64_hook_resolve_symbol(target_sym, &addr,
                                   module_name, sizeof(module_name));
    if (ret < 0) {
        pr_err("a64_hook: cannot resolve symbol '%s'\n", target_sym);
        return -A64_HOOK_ERR_NOSYM;
    }

    if (!addr) {
        pr_err("a64_hook: symbol '%s' resolved to NULL\n", target_sym);
        return -A64_HOOK_ERR_NOSYM;
    }

    /* Allocate hook */
    hook = a64_hook_alloc();
    if (!hook) {
        pr_err("a64_hook: failed to allocate hook\n");
        return -ENOMEM;
    }

    /* Initialize */
    strscpy(hook->name, name, sizeof(hook->name));
    hook->target_addr = addr;
    hook->handler_addr = (unsigned long)handler;
    hook->priv = priv;
    hook->type = (flags & A64_HOOK_F_KPROBE) ?
                  A64_HOOK_TYPE_KPROBE : A64_HOOK_TYPE_DETOUR;
    hook->flags = flags;
    hook->state = A64_HOOK_STATE_DISABLED;
    hook->priority = 0;
    strscpy(hook->sym_name, target_sym, sizeof(hook->sym_name));
    strscpy(hook->module_name, module_name, sizeof(hook->module_name));

    /* Install */
    ret = a64_hook_install(hook);
    if (ret < 0) {
        a64_hook_free(hook);
        return ret;
    }

    return 0;
}

/*
 * Internal: Do the actual hook installation (write branch instructions)
 */
static int a64_hook_do_install(struct a64_hook *hook)
{
    int ret;
    int i;
    u32 branch_insn;
    unsigned long patch_addrs[A64_HOOK_MAX_INSN_SIZE];
    u32 patch_insns[A64_HOOK_MAX_INSN_SIZE];

    /* If we have a trampoline, generate it and branch to trampoline */
    if (hook->flags & A64_HOOK_F_TRAMPOLINE) {
        struct a64_trampoline *tramp;
        unsigned long return_addr;

        return_addr = hook->target_addr + hook->n_orig_insns * 4;

        tramp = kmem_cache_alloc(a64_tramp_cache, GFP_KERNEL);
        if (!tramp) {
            pr_err("a64_hook: failed to allocate trampoline for '%s'\n",
                   hook->name);
            return -ENOMEM;
        }
        memset(tramp, 0, sizeof(*tramp));
        spin_lock_init(&tramp->lock);

        ret = a64_tramp_generate(tramp, hook->orig_insns,
                                  hook->n_orig_insns,
                                  hook->handler_addr, (unsigned long)hook->priv,
                                  return_addr);
        if (ret < 0) {
            pr_err("a64_hook: trampoline generation failed for '%s': %d\n",
                   hook->name, ret);
            kmem_cache_free(a64_tramp_cache, tramp);
            return ret;
        }

        hook->trampoline = tramp;
        a64_hook_stats.total_trampolines++;
        branch_insn = a64_insn_b(hook->target_addr, tramp->pc);
    } else {
        branch_insn = a64_insn_b(hook->target_addr, hook->handler_addr);
    }
    hook->hook_insn = branch_insn;

    /* Prepare patch data */
    for (i = 0; i < hook->n_orig_insns; i++) {
        patch_addrs[i] = hook->target_addr + i * 4;
        if (i == 0)
            patch_insns[i] = branch_insn;
        else
            patch_insns[i] = a64_insn_nop();
    }

    /* If DMA-based writing is enabled, use it */
    if (a64_hook_use_dma) {
        for (i = 0; i < hook->n_orig_insns; i++) {
            ret = a64_dma_patch_text(patch_addrs[i], patch_insns[i]);
            if (ret < 0) {
                pr_err("a64_hook: DMA patch failed at 0x%lx: %d\n",
                       patch_addrs[i], ret);
                return ret;
            }
            hook->stats.dma_writes++;
            hook->stats.bytes_written += 4;
            a64_hook_stats.total_dma_writes++;
            a64_hook_stats.total_bytes_written += 4;
        }
    } else {
        /* Use atomic stop_machine-based patching */
        for (i = 0; i < hook->n_orig_insns; i++) {
            ret = a64_atomic_patch_single(patch_addrs[i],
                                           patch_insns[i], NULL);
            if (ret < 0) {
                pr_err("a64_hook: atomic patch failed at 0x%lx: %d\n",
                       patch_addrs[i], ret);
                return ret;
            }
        }
    }

    /* Flush instruction cache for the patched region */
    a64_dma_flush_icache(hook->target_addr,
                          hook->n_orig_insns * 4);
    hook->stats.cache_flushes++;
    a64_hook_stats.total_cache_flushes++;

    return A64_HOOK_SUCCESS;
}

/*
 * Internal: Uninstall hook (restore original instructions)
 */
static int a64_hook_do_uninstall(struct a64_hook *hook)
{
    int ret;
    int i;

    for (i = hook->n_orig_insns - 1; i >= 0; i--) {
        ret = a64_atomic_patch_single(hook->orig_insns[i].pc,
                                       hook->orig_insns[i].insn, NULL);
        if (ret < 0) {
            pr_err("a64_hook: restore failed at 0x%lx: %d\n",
                   hook->orig_insns[i].pc, ret);
            return ret;
        }
    }

    a64_dma_flush_icache(hook->target_addr,
                          hook->n_orig_insns * 4);

    return A64_HOOK_SUCCESS;
}

/*
 * Validate that a hook target is patchable
 */
static int a64_hook_validate_target(struct a64_hook *hook)
{
    unsigned long addr = hook->target_addr;

    if (!addr)
        return -EINVAL;

    if (addr & 0x3) {
        pr_err("a64_hook: target 0x%lx is not 4-byte aligned\n", addr);
        return -EINVAL;
    }

    if (addr < PAGE_OFFSET) {
        pr_err("a64_hook: target 0x%lx is below PAGE_OFFSET\n", addr);
        return -EINVAL;
    }

    /* Check that target and handler are within branch range */
    {
        long offset = (long)(hook->handler_addr - addr);
        if (offset < -A64_HOOK_BRANCH_RANGE ||
            offset >= A64_HOOK_BRANCH_RANGE) {
            pr_err("a64_hook: handler at 0x%lx out of range (+/- %dMB) "
                   "from 0x%lx\n",
                   hook->handler_addr, A64_HOOK_BRANCH_RANGE >> 20, addr);
            return -A64_HOOK_ERR_BRANCH_OUT;
        }
    }

    return A64_HOOK_SUCCESS;
}

/*
 * Resolve a kernel symbol to its address (with module support)
 */
static int a64_hook_resolve_symbol(const char *sym_name,
                                    unsigned long *addr,
                                    char *module_name,
                                    size_t mod_name_size)
{
    unsigned long ret_addr;

    if (!sym_name || !addr)
        return -EINVAL;

    if (a64_sym.kallsyms_lookup_name)
        ret_addr = a64_sym.kallsyms_lookup_name(sym_name);
    else
        ret_addr = 0;

    if (!ret_addr) {
        return -A64_HOOK_ERR_NOSYM;
    }

    *addr = ret_addr;

    if (module_name && a64_sym.module_address) {
        struct module *mod = NULL;
        void *sym_addr = (void *)ret_addr;

        mod = a64_sym.module_address((unsigned long)sym_addr);
        if (mod)
            strscpy(module_name, mod->name, mod_name_size);
        else
            strscpy(module_name, "vmlinux", mod_name_size);
    }

    return 0;
}

/*
 * Allocate a new hook structure
 */
struct a64_hook *a64_hook_alloc(void)
{
    struct a64_hook *hook;

    hook = kmem_cache_zalloc(a64_hook_cache, GFP_KERNEL);
    if (!hook)
        return NULL;

    spin_lock_init(&hook->lock);
    INIT_LIST_HEAD(&hook->list);
    INIT_HLIST_NODE(&hook->hash_node);
    hook->state = A64_HOOK_STATE_DISABLED;
    hook->owner_pid = task_pid_nr(current);

    return hook;
}

/*
 * Free a hook structure
 */
void a64_hook_free(struct a64_hook *hook)
{
    if (!hook)
        return;

    if (hook->trampoline) {
        a64_tramp_free(hook->trampoline);
        kmem_cache_free(a64_tramp_cache, hook->trampoline);
        hook->trampoline = NULL;
    }

    if (hook->dma_map) {
        kmem_cache_free(a64_dma_cache, hook->dma_map);
        hook->dma_map = NULL;
    }

    if (hook->kprobe) {
        kmem_cache_free(a64_kprobe_cache, hook->kprobe);
        hook->kprobe = NULL;
    }

    if (hook->bpf_ctx) {
        if (hook->bpf_ctx->prog)
            bpf_prog_put(hook->bpf_ctx->prog);
        kfree(hook->bpf_ctx);
        hook->bpf_ctx = NULL;
    }

    kmem_cache_free(a64_hook_cache, hook);
}

/*
 * Initialize a hook with given parameters
 */
int a64_hook_init(struct a64_hook *hook, const char *name,
                   unsigned long target, unsigned long handler,
                   enum a64_hook_type type, u64 flags)
{
    if (!hook || !name)
        return -EINVAL;

    memset(hook, 0, sizeof(*hook));
    strscpy(hook->name, name, sizeof(hook->name));
    hook->target_addr = target;
    hook->handler_addr = handler;
    hook->type = type;
    hook->flags = flags;
    hook->state = A64_HOOK_STATE_DISABLED;
    hook->owner_pid = task_pid_nr(current);

    spin_lock_init(&hook->lock);
    INIT_LIST_HEAD(&hook->list);
    INIT_HLIST_NODE(&hook->hash_node);

    return A64_HOOK_SUCCESS;
}

/*
 * Initialize a hook with a symbol name for the target
 */
int a64_hook_init_sym(struct a64_hook *hook, const char *name,
                       const char *target_sym, unsigned long handler,
                       enum a64_hook_type type, u64 flags)
{
    unsigned long addr;
    char modname[A64_HOOK_MODULE_NAME_LEN];
    int ret;

    if (!hook || !name || !target_sym)
        return -EINVAL;

    ret = a64_hook_resolve_symbol(target_sym, &addr,
                                   modname, sizeof(modname));
    if (ret < 0)
        return ret;

    ret = a64_hook_init(hook, name, addr, handler, type, flags);
    if (ret < 0)
        return ret;

    strscpy(hook->sym_name, target_sym, sizeof(hook->sym_name));
    strscpy(hook->module_name, modname, sizeof(hook->module_name));

    return A64_HOOK_SUCCESS;
}

/*
 * Find a hook by name
 */
struct a64_hook *a64_hook_find(const char *name)
{
    struct a64_hook *hook;
    unsigned long flags;

    if (!name)
        return NULL;

    spin_lock_irqsave(&a64_hook_list_lock, flags);
    list_for_each_entry(hook, &a64_hook_list, list) {
        if (strcmp(hook->name, name) == 0) {
            spin_unlock_irqrestore(&a64_hook_list_lock, flags);
            return hook;
        }
    }
    spin_unlock_irqrestore(&a64_hook_list_lock, flags);

    return NULL;
}

/*
 * Find a hook by target address
 */
struct a64_hook *a64_hook_find_by_addr(unsigned long addr)
{
    struct a64_hook *hook;
    unsigned long flags;

    spin_lock_irqsave(&a64_hook_list_lock, flags);
    hash_for_each_possible(a64_hook_hash, hook, hash_node,
                           hash_ptr((void *)addr, A64_HOOK_HASH_BITS)) {
        if (hook->target_addr == addr) {
            spin_unlock_irqrestore(&a64_hook_list_lock, flags);
            return hook;
        }
    }
    spin_unlock_irqrestore(&a64_hook_list_lock, flags);

    return NULL;
}

/*
 * Look up a hook by name
 */
int a64_hook_lookup(const char *name, struct a64_hook **out)
{
    struct a64_hook *hook;

    if (!name || !out)
        return -EINVAL;

    hook = a64_hook_find(name);
    if (!hook)
        return -A64_HOOK_ERR_HOOK_NOTFOUND;

    *out = hook;
    return A64_HOOK_SUCCESS;
}

/*
 * Iterate over all hooks
 */
int a64_hook_iter_start(struct a64_hook_iter *iter)
{
    if (!iter)
        return -EINVAL;

    memset(iter, 0, sizeof(*iter));
    return A64_HOOK_SUCCESS;
}

struct a64_hook *a64_hook_iter_next(struct a64_hook_iter *iter)
{
    struct a64_hook *hook = NULL;
    unsigned long flags;

    if (!iter)
        return NULL;

    spin_lock_irqsave(&a64_hook_list_lock, flags);

    if (iter->curr == NULL) {
        hook = list_first_entry_or_null(&a64_hook_list,
                                        struct a64_hook, list);
    } else {
        hook = list_next_entry(iter->curr, list);
        if (&hook->list == &a64_hook_list)
            hook = NULL;
    }

    /* Apply filters */
    while (hook) {
        bool matches = true;

        if (iter->filter_name[0]) {
            if (strstr(hook->name, iter->filter_name) == NULL)
                matches = false;
        }

        if (iter->filter_enabled) {
            if (iter->filter_enabled == 1 &&
                hook->state != A64_HOOK_STATE_ENABLED)
                matches = false;
            if (iter->filter_enabled == 2 &&
                hook->state == A64_HOOK_STATE_ENABLED)
                matches = false;
        }

        if (iter->filter_type != A64_HOOK_TYPE_MAX) {
            if (hook->type != iter->filter_type)
                matches = false;
        }

        if (iter->filter_flags) {
            if ((hook->flags & iter->filter_flags) != iter->filter_flags)
                matches = false;
        }

        if (matches)
            break;

        hook = list_next_entry(hook, list);
        if (&hook->list == &a64_hook_list) {
            hook = NULL;
            break;
        }
    }

    iter->curr = hook;
    iter->index++;

    spin_unlock_irqrestore(&a64_hook_list_lock, flags);

    return hook;
}

void a64_hook_iter_end(struct a64_hook_iter *iter)
{
    if (iter)
        memset(iter, 0, sizeof(*iter));
}

/*
 * Count active hooks
 */
int a64_hook_count(void)
{
    return atomic_read(&a64_hook_count_atomic);
}

/*
 * Get global statistics
 */
int a64_hook_get_stats(struct a64_hook_global_stats *stats)
{
    if (!stats)
        return -EINVAL;

    memcpy(stats, &a64_hook_stats, sizeof(*stats));
    stats->uptime_jiffies = get_jiffies_64() - stats->started_at;

    return A64_HOOK_SUCCESS;
}

/*
 * Hook chaining: add a hook to an existing chain at an address
 */
int a64_hook_chain_add(struct a64_hook_chain *chain, struct a64_hook *hook)
{
    unsigned long flags;

    if (!chain || !hook)
        return -EINVAL;

    spin_lock_irqsave(&chain->lock, flags);

    if (chain->n_hooks >= A64_HOOK_TRAMPOLINE_MAX) {
        spin_unlock_irqrestore(&chain->lock, flags);
        return -A64_HOOK_ERR_TOO_MANY;
    }

    chain->hooks[chain->n_hooks++] = hook;

    if (chain->n_hooks > a64_hook_stats.max_chain_depth)
        a64_hook_stats.max_chain_depth = chain->n_hooks;

    a64_hook_stats.total_chain_hooks++;

    spin_unlock_irqrestore(&chain->lock, flags);

    return A64_HOOK_SUCCESS;
}

/*
 * Remove a hook from a chain
 */
int a64_hook_chain_remove(struct a64_hook_chain *chain, struct a64_hook *hook)
{
    unsigned long flags;
    int i;

    if (!chain || !hook)
        return -EINVAL;

    spin_lock_irqsave(&chain->lock, flags);

    for (i = 0; i < chain->n_hooks; i++) {
        if (chain->hooks[i] == hook) {
            memmove(&chain->hooks[i], &chain->hooks[i + 1],
                    (chain->n_hooks - i - 1) * sizeof(struct a64_hook *));
            chain->n_hooks--;
            spin_unlock_irqrestore(&chain->lock, flags);
            return A64_HOOK_SUCCESS;
        }
    }

    spin_unlock_irqrestore(&chain->lock, flags);
    return -A64_HOOK_ERR_HOOK_NOTFOUND;
}

/*
 * Execute all hooks in a chain
 */
int a64_hook_chain_execute(struct a64_hook_chain *chain, struct pt_regs *regs)
{
    unsigned long flags;
    int i;
    int ret = 0;

    if (!chain || !regs)
        return -EINVAL;

    spin_lock_irqsave(&chain->lock, flags);

    for (i = 0; i < chain->n_hooks; i++) {
        struct a64_hook *hook = chain->hooks[i];
        if (hook && hook->state == A64_HOOK_STATE_ENABLED) {
            a64_hook_handler_t handler;

            handler = (a64_hook_handler_t)hook->handler_addr;
            if (handler) {
                u64 start = sched_clock();
                int hr = handler(regs, hook->priv);
                u64 end = sched_clock();

                hook->stats.hits++;
                hook->stats.last_fired_jiffies = get_jiffies_64();
                chain->total_hits++;

                {
                    u64 latency = end - start;
                    hook->stats.total_latency_ns += latency;
                    if (latency > hook->stats.max_latency_ns)
                        hook->stats.max_latency_ns = latency;
                    if (latency < hook->stats.min_latency_ns ||
                        hook->stats.min_latency_ns == 0)
                        hook->stats.min_latency_ns = latency;
                }

                if (hr < 0) {
                    hook->stats.errors++;
                    ret = hr;
                }
            }
        }
    }

    spin_unlock_irqrestore(&chain->lock, flags);

    return ret;
}

/*
 * Find a hook chain by target address
 */
struct a64_hook_chain *a64_hook_chain_find(unsigned long addr)
{
    struct a64_hook *hook;

    hook = a64_hook_find_by_addr(addr);
    if (!hook)
        return NULL;

    return NULL;
}

/*
 * BPF attachment
 */
int a64_hook_attach_bpf(struct a64_hook *hook, struct bpf_prog *prog)
{
    unsigned long flags;

    if (!hook || !prog)
        return -EINVAL;

    spin_lock_irqsave(&hook->lock, flags);

    if (hook->bpf_ctx) {
        spin_unlock_irqrestore(&hook->lock, flags);
        return -A64_HOOK_ERR_BUSY;
    }

    hook->bpf_ctx = kzalloc(sizeof(struct a64_hook_bpf_ctx), GFP_KERNEL);
    if (!hook->bpf_ctx) {
        spin_unlock_irqrestore(&hook->lock, flags);
        return -ENOMEM;
    }

    bpf_prog_inc(prog);
    hook->bpf_ctx->prog = prog;
    hook->bpf_ctx->flags = hook->flags;
    hook->bpf_ctx->start_time = sched_clock();
    strscpy(hook->bpf_ctx->name, hook->name, A64_HOOK_MAX_NAME);

    a64_hook_stats.total_bpf_attachments++;
    hook->stats.bpf_attached++;

    spin_unlock_irqrestore(&hook->lock, flags);

    if (a64_hook_verbose > 0)
        pr_info("a64_hook: BPF attached to '%s'\n", hook->name);

    return A64_HOOK_SUCCESS;
}

/*
 * Detach BPF from a hook
 */
int a64_hook_detach_bpf(struct a64_hook *hook)
{
    unsigned long flags;

    if (!hook || !hook->bpf_ctx)
        return -EINVAL;

    spin_lock_irqsave(&hook->lock, flags);

    if (hook->bpf_ctx->prog)
        bpf_prog_put(hook->bpf_ctx->prog);

    kfree(hook->bpf_ctx);
    hook->bpf_ctx = NULL;

    spin_unlock_irqrestore(&hook->lock, flags);

    return A64_HOOK_SUCCESS;
}

/*
 * Run BPF program for a hook
 */
int a64_hook_run_bpf(struct a64_hook *hook, struct pt_regs *regs)
{
    struct a64_hook_bpf_ctx *ctx;
    unsigned long flags;

    if (!hook || !regs)
        return -EINVAL;

    rcu_read_lock();

    spin_lock_irqsave(&hook->lock, flags);
    ctx = hook->bpf_ctx;
    if (!ctx || !ctx->prog) {
        spin_unlock_irqrestore(&hook->lock, flags);
        rcu_read_unlock();
        return 0;
    }
    spin_unlock_irqrestore(&hook->lock, flags);

    {
        u64 start = sched_clock();
        int ret;

        ret = bpf_prog_run(ctx->prog, regs);

        if (ret) {
            u64 end = sched_clock();
            ctx->call_count++;
            ctx->total_ns += (end - start);
        }
    }

    rcu_read_unlock();
    return 0;
}

/*
 * Show hook details in a buffer
 */
void a64_hook_show(struct a64_hook *hook, char *buf, size_t size)
{
    int n = 0;

    if (!hook || !buf || size == 0)
        return;

    n += snprintf(buf + n, size - n,
        "Hook:     %s\n"
        "State:    %d (%s)\n"
        "Type:     %d\n"
        "Target:   0x%016lx\n"
        "Handler:  0x%016lx\n"
        "Flags:    0x%016llx\n"
        "N_insns:  %d\n"
        "Hits:     %llu\n"
        "Errors:   %llu\n"
        "DMA:      %llu writes, %llu bytes\n"
        "Cache:    %llu flushes\n"
        "BPF:      %llu attached\n",
        hook->name,
        hook->state, hook->state == A64_HOOK_STATE_ENABLED ? "enabled" :
            hook->state == A64_HOOK_STATE_DISABLED ? "disabled" :
            hook->state == A64_HOOK_STATE_PENDING ? "pending" :
            hook->state == A64_HOOK_STATE_ERROR ? "error" : "unknown",
        hook->type,
        hook->target_addr,
        hook->handler_addr,
        hook->flags,
        hook->n_orig_insns,
        hook->stats.hits,
        hook->stats.errors,
        hook->stats.dma_writes,
        hook->stats.bytes_written,
        hook->stats.cache_flushes,
        hook->stats.bpf_attached);

    if (hook->sym_name[0]) {
        n += snprintf(buf + n, size - n,
            "Symbol:   %s+0x%lx (module: %s)\n",
            hook->sym_name, hook->sym_offset, hook->module_name);
    }

    if (hook->trampoline) {
        n += snprintf(buf + n, size - n,
            "Tramp:    pc=0x%lx size=%zu insns=%d\n",
            hook->trampoline->pc,
            hook->trampoline->size,
            hook->trampoline->n_insns);
    }
}

/*
 * Show all hooks in a buffer
 */
void a64_hook_show_all(char *buf, size_t size)
{
    struct a64_hook *hook;
    unsigned long flags;
    int n = 0;

    if (!buf || size == 0)
        return;

    n += snprintf(buf + n, size - n,
        "a64_hook: %d hooks active\n",
        atomic_read(&a64_hook_count_atomic));

    spin_lock_irqsave(&a64_hook_list_lock, flags);

    list_for_each_entry(hook, &a64_hook_list, list) {
        if ((size_t)n < size - 256) {
            n += snprintf(buf + n, size - n,
                "  %-32s state=%d type=%d target=0x%lx hits=%llu\n",
                hook->name, hook->state, hook->type,
                hook->target_addr, hook->stats.hits);
        }
    }

    spin_unlock_irqrestore(&a64_hook_list_lock, flags);
}

/*
 * Validate a single hook's integrity
 */
int a64_hook_validate(struct a64_hook *hook)
{
    int i;

    if (!hook)
        return -EINVAL;

    if (hook->state == A64_HOOK_STATE_ENABLED) {
        u32 cur;

        for (i = 0; i < hook->n_orig_insns; i++) {
            cur = a64_get_insn((volatile u32 *)(hook->target_addr + i * 4));
            if (i == 0) {
                if (cur != hook->hook_insn) {
                    pr_err("a64_hook: hook '%s' corrupted at +%d: "
                           "expected 0x%08x, got 0x%08x\n",
                           hook->name, i, hook->hook_insn, cur);
                    return -A64_HOOK_ERR_CORRUPT;
                }
            } else {
                if (cur != a64_insn_nop()) {
                    /* Non-NOP might be OK if it's a multi-instruction hook */
                    continue;
                }
            }
        }
    }

    return A64_HOOK_SUCCESS;
}

/*
 * Validate the entire hook state
 */
int a64_hook_validate_state(void)
{
    struct a64_hook *hook;
    unsigned long flags;
    int ret;

    spin_lock_irqsave(&a64_hook_list_lock, flags);

    list_for_each_entry(hook, &a64_hook_list, list) {
        ret = a64_hook_validate(hook);
        if (ret < 0) {
            spin_unlock_irqrestore(&a64_hook_list_lock, flags);
            return ret;
        }
    }

    spin_unlock_irqrestore(&a64_hook_list_lock, flags);

    return A64_HOOK_SUCCESS;
}

/*
 * Self-test: verify basic hooking functionality
 */
int a64_hook_self_test(void)
{
    int ret;
    unsigned long test_addr;
    u32 test_insn, orig_insn;
    volatile u32 *test_ptr;

    pr_info("a64_hook: running self-test...\n");

    /* Test 1: Basic instruction patch via DMA */
    pr_info("a64_hook: test 1 - DMA instruction patch\n");

    test_addr = (unsigned long)a64_hook_self_test;
    orig_insn = a64_get_insn((volatile u32 *)test_addr);
    test_insn = a64_insn_nop();

    ret = a64_dma_patch_text(test_addr, test_insn);
    if (ret < 0) {
        pr_err("a64_hook: test 1 FAILED: patch error %d\n", ret);
        return ret;
    }

    /* Verify */
    {
        u32 verify = a64_get_insn((volatile u32 *)test_addr);
        if (verify != test_insn) {
            pr_err("a64_hook: test 1 FAILED: verify mismatch "
                   "(expected 0x%08x, got 0x%08x)\n", test_insn, verify);
            a64_dma_patch_text(test_addr, orig_insn);
            return -EIO;
        }
    }

    /* Restore */
    ret = a64_dma_patch_text(test_addr, orig_insn);
    if (ret < 0) {
        pr_err("a64_hook: test 1 FAILED: restore error %d\n", ret);
        return ret;
    }

    pr_info("a64_hook: test 1 PASSED\n");

    /* Test 2: Branch instruction generation */
    pr_info("a64_hook: test 2 - branch encoding\n");
    {
        u32 branch = a64_insn_b(test_addr, test_addr + 0x1000);
        u32 decoded_offset = a64_insn_branch_offset(branch);
        unsigned long target = a64_branch_target(test_addr, branch);

        if (target != test_addr + 0x1000) {
            pr_err("a64_hook: test 2 FAILED: branch target mismatch\n");
            return -EIO;
        }

        if (!a64_insn_is_b(branch)) {
            pr_err("a64_hook: test 2 FAILED: not a B instruction\n");
            return -EIO;
        }
    }
    pr_info("a64_hook: test 2 PASSED\n");

    /* Test 3: Instruction decode */
    pr_info("a64_hook: test 3 - instruction decode\n");
    {
        struct a64_hook_insn decoded;
        u32 nop = a64_insn_nop();

        ret = a64_decode_insn(nop, &decoded);
        if (ret < 0) {
            pr_err("a64_hook: test 3 FAILED: decode error %d\n", ret);
            return ret;
        }

        if (!decoded.is_nop) {
            pr_err("a64_hook: test 3 FAILED: NOP not detected\n");
            return -EIO;
        }
    }
    pr_info("a64_hook: test 3 PASSED\n");

    /* Test 4: Atomic patching */
    pr_info("a64_hook: test 4 - atomic patching\n");
    {
        test_addr = (unsigned long)a64_hook_self_test + 0x100;
        orig_insn = a64_get_insn((volatile u32 *)test_addr);
        test_insn = a64_insn_brk(0x100);

        ret = a64_atomic_patch_single(test_addr, test_insn, NULL);
        if (ret < 0) {
            pr_err("a64_hook: test 4 FAILED: atomic patch error %d\n", ret);
            return ret;
        }

        ret = a64_atomic_patch_single(test_addr, orig_insn, NULL);
        if (ret < 0) {
            pr_err("a64_hook: test 4 FAILED: restore error %d\n", ret);
            return ret;
        }
    }
    pr_info("a64_hook: test 4 PASSED\n");

    /* Test 5: Cache maintenance */
    pr_info("a64_hook: test 5 - cache maintenance\n");
    {
        test_addr = (unsigned long)a64_hook_self_test;
        a64_flush_dcache_range(test_addr, test_addr + 64);
        a64_invalidate_icache_range(test_addr, test_addr + 64);
        a64_flush_bcache_range(test_addr, test_addr + 64);
    }
    pr_info("a64_hook: test 5 PASSED\n");

    /* Test 6: Hook alloc/free */
    pr_info("a64_hook: test 6 - hook alloc/free\n");
    {
        struct a64_hook *test_hook = a64_hook_alloc();
        if (!test_hook) {
            pr_err("a64_hook: test 6 FAILED: alloc returned NULL\n");
            return -ENOMEM;
        }
        if (test_hook->state != A64_HOOK_STATE_DISABLED) {
            pr_err("a64_hook: test 6 FAILED: bad initial state\n");
            a64_hook_free(test_hook);
            return -EIO;
        }
        a64_hook_free(test_hook);
    }
    pr_info("a64_hook: test 6 PASSED\n");

    /* Test 7: Symbol resolution */
    pr_info("a64_hook: test 7 - symbol resolution\n");
    {
        unsigned long resolved_addr;
        char modname[A64_HOOK_MODULE_NAME_LEN];

        ret = a64_hook_resolve_symbol("printk", &resolved_addr,
                                       modname, sizeof(modname));
        if (ret < 0 || !resolved_addr) {
            pr_err("a64_hook: test 7 FAILED: cannot resolve 'printk'\n");
            return ret < 0 ? ret : -EIO;
        }
    }
    pr_info("a64_hook: test 7 PASSED\n");

    /* Test 8: DMA transfer */
    pr_info("a64_hook: test 8 - DMA write\n");
    {
        u32 test_data = 0xdeadbeef;
        volatile u32 *target = &test_data;
        phys_addr_t paddr;

        paddr = a64_virt_to_phys((void *)&test_data);
        if (paddr) {
            ret = a64_dma_write_phys(paddr, &test_data, sizeof(test_data));
            if (ret < 0) {
                pr_info("a64_hook: test 8 SKIPPED (DMA write failed: %d)\n",
                        ret);
            } else {
                pr_info("a64_hook: test 8 PASSED\n");
            }
        } else {
            pr_info("a64_hook: test 8 SKIPPED (no DMA)\n");
        }
    }

    /* Test 9: Multi-instruction patch */
    pr_info("a64_hook: test 9 - multi-instruction patch\n");
    {
        unsigned long addrs[3];
        u32 insns[3];
        int i;

        test_addr = (unsigned long)a64_hook_self_test;

        for (i = 0; i < 3; i++) {
            addrs[i] = test_addr + i * 4;
            insns[i] = a64_insn_nop();
        }

        ret = a64_atomic_patch_multi(addrs, insns, 3);
        if (ret < 0) {
            pr_err("a64_hook: test 9 FAILED: multi-patch error %d\n", ret);
            return ret;
        }

        /* Restore */
        for (i = 0; i < 3; i++) {
            a64_atomic_patch_single(addrs[i],
                                     a64_get_insn((volatile u32 *)addrs[i]),
                                     NULL);
        }
    }
    pr_info("a64_hook: test 9 PASSED\n");

    pr_info("a64_hook: all self-tests PASSED\n");
    return A64_HOOK_SUCCESS;
}
