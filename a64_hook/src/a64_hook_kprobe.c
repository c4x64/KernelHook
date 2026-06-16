/*
 * a64_hook_kprobe.c - Kprobe Fallback Integration
 *
 * Provides kprobe-based hooking as a fallback mechanism when direct
 * inline patching is unavailable or unsafe. Supports both kprobes and
 * kretprobes for function entry/exit hooking.
 *
 * License: GPL v2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/ptrace.h>

#include "a64_hook.h"
#include "a64_hook_sym.h"

static int a64_kprobe_pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
    struct a64_kprobe_entry *entry;

    entry = container_of(kp, struct a64_kprobe_entry, kp);
    if (!entry)
        return 0;

    if (entry->pre_handler) {
        unsigned long flags;
        spin_lock_irqsave(&entry->lock, flags);
        entry->registered = true;
        spin_unlock_irqrestore(&entry->lock, flags);
        return entry->pre_handler(regs, entry->priv);
    }

    return 0;
}

static void a64_kprobe_post_handler(struct kprobe *kp, struct pt_regs *regs,
                                     unsigned long flags)
{
    struct a64_kprobe_entry *entry;

    entry = container_of(kp, struct a64_kprobe_entry, kp);
    if (!entry)
        return;

    if (entry->post_handler)
        entry->post_handler(regs, entry->priv);
}

static int a64_kprobe_fault_handler(struct kprobe *kp, struct pt_regs *regs,
                                     int trapnr)
{
    struct a64_kprobe_entry *entry;

    entry = container_of(kp, struct a64_kprobe_entry, kp);
    if (!entry)
        return 0;

    if (entry->fault_handler)
        return entry->fault_handler(regs, entry->priv);

    return 0;
}

static int a64_kretprobe_entry_handler(struct kretprobe_instance *ri,
                                        struct pt_regs *regs)
{
    struct kretprobe *krp = rcu_dereference_check(ri->rph->rp, rcu_read_lock_any_held());
    struct a64_kprobe_entry *entry;
    entry = container_of(krp, struct a64_kprobe_entry, rp);
    if (!entry)
        return 0;

    if (entry->pre_handler)
        return entry->pre_handler(regs, entry->priv);

    return 0;
}

static int a64_kretprobe_ret_handler(struct kretprobe_instance *ri,
                                      struct pt_regs *regs)
{
    struct a64_kprobe_entry *entry;
    struct kretprobe *krp = rcu_dereference_check(ri->rph->rp, rcu_read_lock_any_held());

    entry = container_of(krp, struct a64_kprobe_entry, rp);
    if (!entry)
        return 0;

    if (entry->post_handler)
        entry->post_handler(regs, entry->priv);

    return 0;
}

int a64_kprobe_register(struct a64_kprobe_entry *entry)
{
    int ret;

    if (!entry)
        return -EINVAL;

    if (!entry->addr && entry->sym_name[0]) {
        if (a64_sym.kallsyms_lookup_name)
            entry->addr = a64_sym.kallsyms_lookup_name(entry->sym_name);
        if (!entry->addr)
            return -A64_HOOK_ERR_NOSYM;
    }

    if (!entry->addr)
        return -EINVAL;

    if (entry->is_kretprobe) {
        entry->rp.handler = a64_kretprobe_ret_handler;
        entry->rp.entry_handler = a64_kretprobe_entry_handler;
        entry->rp.kp.addr = (void *)entry->addr;
        entry->rp.kp.symbol_name = entry->sym_name[0] ? entry->sym_name : NULL;
        entry->rp.maxactive = 32;

        ret = register_kretprobe(&entry->rp);
        if (ret < 0) {
            pr_err("a64_hook: kretprobe register failed at 0x%lx: %d\n",
                   entry->addr, ret);
            return -A64_HOOK_ERR_KPROBE;
        }
    } else {
        entry->kp.pre_handler = a64_kprobe_pre_handler;
        entry->kp.post_handler = a64_kprobe_post_handler;
        entry->kp.addr = (void *)entry->addr;
        entry->kp.symbol_name = entry->sym_name[0] ? entry->sym_name : NULL;

        ret = register_kprobe(&entry->kp);
        if (ret < 0) {
            pr_err("a64_hook: kprobe register failed at 0x%lx: %d\n",
                   entry->addr, ret);
            return -A64_HOOK_ERR_KPROBE;
        }
    }

    entry->registered = true;
    a64_hook_stats.total_kprobe_fallbacks++;

    return 0;
}

int a64_kprobe_unregister(struct a64_kprobe_entry *entry)
{
    if (!entry || !entry->registered)
        return -EINVAL;

    if (entry->is_kretprobe)
        unregister_kretprobe(&entry->rp);
    else
        unregister_kprobe(&entry->kp);

    entry->registered = false;

    return 0;
}

int a64_kprobe_install(struct a64_hook *hook)
{
    struct a64_kprobe_entry *entry;
    int ret;

    if (!hook)
        return -EINVAL;

    entry = kmem_cache_zalloc(a64_kprobe_cache, GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    entry->pre_handler = (a64_hook_handler_t)hook->handler_addr;
    entry->post_handler = NULL;
    entry->fault_handler = NULL;
    entry->priv = hook->priv;
    entry->addr = hook->target_addr;
    entry->is_kretprobe = (hook->type == A64_HOOK_TYPE_RETPROBE);
    strscpy(entry->sym_name, hook->sym_name, sizeof(entry->sym_name));
    spin_lock_init(&entry->lock);

    ret = a64_kprobe_register(entry);
    if (ret < 0) {
        kmem_cache_free(a64_kprobe_cache, entry);
        return ret;
    }

    hook->kprobe = entry;

    return 0;
}

int a64_kprobe_remove(struct a64_hook *hook)
{
    int ret;

    if (!hook || !hook->kprobe)
        return -EINVAL;

    ret = a64_kprobe_unregister(hook->kprobe);
    if (ret < 0)
        return ret;

    kmem_cache_free(a64_kprobe_cache, hook->kprobe);
    hook->kprobe = NULL;

    return 0;
}

int a64_kprobe_enable(struct a64_kprobe_entry *entry)
{
    if (!entry)
        return -EINVAL;

    if (!entry->registered) {
        return a64_kprobe_register(entry);
    }

    return 0;
}

int a64_kprobe_disable(struct a64_kprobe_entry *entry)
{
    if (!entry)
        return -EINVAL;

    if (entry->registered) {
        return a64_kprobe_unregister(entry);
    }

    return 0;
}

bool a64_kprobe_available(void)
{
#ifdef CONFIG_KPROBES
    return true;
#else
    return false;
#endif
}
