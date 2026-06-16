#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cpu.h>
#include <linux/stop_machine.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/hardirq.h>
#include <linux/preempt.h>
#include <linux/interrupt.h>
#include <linux/irqflags.h>
#include <linux/atomic.h>
#include <linux/percpu.h>
#include <linux/cache.h>
#include <linux/mman.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/set_memory.h>
#include <linux/proc_fs.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <asm/cacheflush.h>
#include <asm/barrier.h>
#include <asm/tlbflush.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/io.h>
#include <asm/smp_plat.h>
#include <asm/atomic.h>
#include <asm/unaligned.h>

#include "a64_hook.h"
#include "a64_hook_sym.h"

extern int a64_vfb_init(void);
extern void a64_vfb_exit(void);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("a64-hook");
MODULE_DESCRIPTION("ARM64 AArch64 Inline Hook Engine - DMA-based physmem patching");
MODULE_VERSION(A64_HOOK_VERSION_STRING);

/* Module configuration (defaults only) */
static unsigned int max_hooks = A64_HOOK_MAX_HOOKS;
static bool use_kprobes = true;
static bool use_dma = false;
static bool use_stop_machine = false;
static unsigned int verbose = 0;
static unsigned int debug = 0;
static unsigned int preferred_type = 0;
static unsigned long dma_mask = DMA_BIT_MASK(64);
static bool self_test_on_load = false;

/* Global data */
LIST_HEAD(a64_hook_list);
spinlock_t a64_hook_list_lock;
struct a64_hook_global_stats a64_hook_stats;
struct a64_hook_percpu __percpu *a64_hook_percpu_stats;
struct kmem_cache *a64_hook_cache;
struct kmem_cache *a64_tramp_cache;
struct kmem_cache *a64_kprobe_cache;
struct kmem_cache *a64_dma_cache;
atomic_t a64_hook_count_atomic;
atomic_t a64_hook_enabled_count;
struct dentry *a64_hook_debugfs_dir;

unsigned int a64_hook_verbose;
unsigned int a64_hook_debug;
unsigned int a64_hook_max_hooks;
bool a64_hook_use_kprobes;
bool a64_hook_use_dma;
bool a64_hook_use_stop_machine;

/* Lifecycle control */
static DECLARE_WAIT_QUEUE_HEAD(a64_hook_exit_wq);
static int a64_hook_exit_flag;
static struct proc_dir_entry *a64_hook_proc_entry;

/* Forward declarations */
static int a64_hook_proc_show(struct seq_file *m, void *v);
static int a64_hook_cmd_open(struct inode *inode, struct file *file);
static ssize_t a64_hook_cmd_write(struct file *file, const char __user *buf,
                                   size_t len, loff_t *off);
static int a64_hook_cmd_release(struct inode *inode, struct file *file);

/* Default hook handler: counts hits and returns (doesn't block original func) */
struct a64_hook_counter {
    atomic64_t hits;
    char func_name[64];
};

static int a64_hook_default_handler(struct pt_regs *regs, void *priv)
{
    struct a64_hook_counter *counter = priv;
    if (counter && counter->func_name[0])
        a64_gui_hook_notify(counter->func_name,
                            regs ? regs->pc : 0, regs);
    if (counter)
        atomic64_inc(&counter->hits);
    return 0;
}

static int a64_hook_cmd_open(struct inode *inode, struct file *file)
{
    return single_open(file, a64_hook_proc_show, inode->i_private);
}

static int a64_hook_cmd_release(struct inode *inode, struct file *file)
{
    return single_release(inode, file);
}

#ifdef CONFIG_PROC_FS
static const struct proc_ops a64_hook_cmd_fops = {
    .proc_open    = a64_hook_cmd_open,
    .proc_read    = seq_read,
    .proc_write   = a64_hook_cmd_write,
    .proc_release = a64_hook_cmd_release,
    .proc_lseek   = seq_lseek,
};
#else
static const struct file_operations a64_hook_cmd_fops = {
    .owner   = THIS_MODULE,
    .open    = a64_hook_cmd_open,
    .read    = seq_read,
    .write   = a64_hook_cmd_write,
    .release = a64_hook_cmd_release,
    .llseek  = seq_lseek,
};
#endif

/*
 * IOCTL handler for /dev/a64_hook
 */
static long a64_hook_ioctl(struct file *filp, unsigned int cmd,
                            unsigned long arg)
{
    void __user *argp = (void __user *)arg;

    switch (cmd) {
    case A64_IOC_GUI_CLEAR:
    case A64_IOC_GUI_TEXT:
    case A64_IOC_GUI_RECT:
    case A64_IOC_GUI_PIXEL:
    case A64_IOC_GUI_GETFB:
        return a64_gui_ioctl(cmd, arg);

    case A64_IOC_HOOK:
    case A64_IOC_KPROBE: {
        struct a64_ioc_hook req;
        int ret;
        unsigned int flags = A64_HOOK_DEFAULT_FLAGS;

        if (copy_from_user(&req, argp, sizeof(req)))
            return -EFAULT;

        if (cmd == A64_IOC_KPROBE)
            flags |= A64_HOOK_F_KPROBE;

        ret = a64_hook_install_by_name(req.name, req.sym,
                    a64_hook_default_handler, NULL, flags);
        req.result = ret;
        if (copy_to_user(argp, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case A64_IOC_UNHOOK: {
        struct a64_ioc_unhook req;
        struct a64_hook *hook;

        if (copy_from_user(&req, argp, sizeof(req)))
            return -EFAULT;

        hook = a64_hook_find(req.name);
        if (!hook) {
            req.result = -ENOENT;
        } else {
            a64_hook_remove(hook);
            req.result = 0;
        }
        if (copy_to_user(argp, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case A64_IOC_LIST: {
        struct a64_ioc_list resp;
        struct a64_hook *hook;
        unsigned long flags;
        int i = 0;

        memset(&resp, 0, sizeof(resp));
        spin_lock_irqsave(&a64_hook_list_lock, flags);
        list_for_each_entry(hook, &a64_hook_list, list) {
            if (i >= A64_IOC_MAX_HOOKS) break;
            strscpy(resp.hooks[i].name, hook->name,
                    sizeof(resp.hooks[i].name));
            resp.hooks[i].target_addr = hook->target_addr;
            resp.hooks[i].handler_addr = hook->handler_addr;
            resp.hooks[i].type = hook->type;
            resp.hooks[i].state = hook->state;
            resp.hooks[i].hits = hook->stats.hits;
            strscpy(resp.hooks[i].sym, hook->sym_name,
                    sizeof(resp.hooks[i].sym));
            i++;
        }
        spin_unlock_irqrestore(&a64_hook_list_lock, flags);
        resp.count = i;
        if (copy_to_user(argp, &resp, sizeof(resp)))
            return -EFAULT;
        return 0;
    }

    case A64_IOC_STATS: {
        struct a64_ioc_stats resp;
        struct a64_hook_global_stats s;

        a64_hook_get_stats(&s);
        memset(&resp, 0, sizeof(resp));
        resp.uptime_jiffies = s.uptime_jiffies;
        resp.total_hooks = s.total_hooks;
        resp.enabled_hooks = s.enabled_hooks;
        resp.disabled_hooks = s.disabled_hooks;
        resp.error_hooks = s.error_hooks;
        resp.total_hits = s.total_hits;
        resp.dma_writes = s.total_dma_writes;
        resp.bytes_written = s.total_bytes_written;
        resp.cache_flushes = s.total_cache_flushes;
        resp.trampolines = s.total_trampolines;
        resp.kprobe_fallbacks = s.total_kprobe_fallbacks;
        resp.peak_hooks = s.peak_hook_count;

        if (copy_to_user(argp, &resp, sizeof(resp)))
            return -EFAULT;
        return 0;
    }

    case A64_IOC_HITS: {
        struct a64_ioc_hits req;
        struct a64_hook *hook;

        if (copy_from_user(&req, argp, sizeof(req)))
            return -EFAULT;

        hook = a64_hook_find(req.name);
        if (!hook) {
            req.result = -ENOENT;
            req.hits = 0;
        } else {
            req.hits = hook->stats.hits;
            req.result = 0;
        }
        if (copy_to_user(argp, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    case A64_IOC_CLEAR:
        memset(&a64_hook_stats, 0, sizeof(a64_hook_stats));
        return 0;

    case A64_IOC_SELFTEST: {
        int ret = a64_hook_self_test();
        return ret < 0 ? ret : 0;
    }

    default:
        return -ENOTTY;
    }
}

static const struct file_operations a64_hook_dev_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = a64_hook_ioctl,
    .compat_ioctl   = a64_hook_ioctl,
};

static struct miscdevice a64_hook_misc = {
    .minor  = MISC_DYNAMIC_MINOR,
    .name   = "a64_hook",
    .fops   = &a64_hook_dev_fops,
};

static int a64_hook_proc_show(struct seq_file *m, void *v)
{
    struct a64_hook *hook;
    struct a64_hook_global_stats stats;
    unsigned long flags;

    a64_hook_get_stats(&stats);

    seq_printf(m, "=== a64_hook v" A64_HOOK_VERSION_STRING " ===\n");
    seq_printf(m, "Uptime:         %llu jiffies\n", stats.uptime_jiffies);
    seq_printf(m, "Total hooks:    %llu\n", stats.total_hooks);
    seq_printf(m, "Enabled:        %llu\n", stats.enabled_hooks);
    seq_printf(m, "Disabled:       %llu\n", stats.disabled_hooks);
    seq_printf(m, "Errors:         %llu\n", stats.error_hooks);
    seq_printf(m, "Total hits:     %llu\n", stats.total_hits);
    seq_printf(m, "DMA writes:     %llu\n", stats.total_dma_writes);
    seq_printf(m, "Bytes written:  %llu\n", stats.total_bytes_written);
    seq_printf(m, "Cache flushes:  %llu\n", stats.total_cache_flushes);
    seq_printf(m, "Trampolines:    %llu\n", stats.total_trampolines);
    seq_printf(m, "DMA mappings:   %llu\n", stats.total_dma_mappings);
    seq_printf(m, "Kprobe fbacks:  %llu\n", stats.total_kprobe_fallbacks);
    seq_printf(m, "BPF attach:     %llu\n", stats.total_bpf_attachments);
    seq_printf(m, "Chain depth:    %llu\n", stats.max_chain_depth);
    seq_printf(m, "OOM count:      %llu\n", stats.oom_count);
    seq_printf(m, "Peak hooks:     %llu\n", stats.peak_hook_count);
    seq_printf(m, "Stop machine:   %llu\n\n", stats.stop_machine_calls);

    spin_lock_irqsave(&a64_hook_list_lock, flags);

    seq_printf(m, "%-32s %-12s %-10s %-18s %-8s %s\n",
               "Name", "Type", "State", "Target", "Hits", "Symbol");
    seq_printf(m, "%-32s %-12s %-10s %-18s %-8s %s\n",
               "--------------------------------", "----------", "---------",
               "------------------", "--------", "------");

    list_for_each_entry(hook, &a64_hook_list, list) {
        const char *type_str = "UNKNOWN";
        const char *state_str = "UNKNOWN";

        switch (hook->type) {
        case A64_HOOK_TYPE_INLINE:  type_str = "INLINE"; break;
        case A64_HOOK_TYPE_DETOUR:  type_str = "DETOUR"; break;
        case A64_HOOK_TYPE_KPROBE:  type_str = "KPROBE"; break;
        case A64_HOOK_TYPE_BL:      type_str = "BL";     break;
        case A64_HOOK_TYPE_BR:      type_str = "BR";     break;
        case A64_HOOK_TYPE_BLR:     type_str = "BLR";    break;
        case A64_HOOK_TYPE_DMA_ONLY: type_str = "DMA";   break;
        default: break;
        }

        switch (hook->state) {
        case A64_HOOK_STATE_ENABLED:  state_str = "ENABLED";  break;
        case A64_HOOK_STATE_DISABLED: state_str = "DISABLED"; break;
        case A64_HOOK_STATE_PENDING:  state_str = "PENDING";  break;
        case A64_HOOK_STATE_ERROR:    state_str = "ERROR";    break;
        case A64_HOOK_STATE_REMOVING: state_str = "REMOVING"; break;
        default: break;
        }

        seq_printf(m, "%-32s %-12s %-10s 0x%016lx %-8llu",
                   hook->name, type_str, state_str,
                   hook->target_addr, hook->stats.hits);

        if (hook->sym_name[0])
            seq_printf(m, " %s+0x%lx", hook->sym_name, hook->sym_offset);

        seq_printf(m, "\n");
    }

    spin_unlock_irqrestore(&a64_hook_list_lock, flags);

    return 0;
}

static ssize_t a64_hook_cmd_write(struct file *file,
                                   const char __user *buf,
                                   size_t len, loff_t *off)
{
    char cmd[256], name[64];
    int ret;

    if (len >= sizeof(cmd))
        return -EINVAL;

    if (copy_from_user(cmd, buf, len))
        return -EFAULT;

    cmd[len] = '\0';

    if (cmd[len - 1] == '\n')
        cmd[len - 1] = '\0';

    if (strcmp(cmd, "exit") == 0) {
        a64_hook_exit_flag = 1;
        wake_up(&a64_hook_exit_wq);
    } else if (strncmp(cmd, "selftest", 8) == 0) {
        ret = a64_hook_self_test();
    } else if (strncmp(cmd, "stats", 5) == 0) {
        struct a64_hook_global_stats s;
        a64_hook_get_stats(&s);
    } else if (strncmp(cmd, "clear", 5) == 0) {
        memset(&a64_hook_stats, 0, sizeof(a64_hook_stats));
    } else if (strncmp(cmd, "validate", 8) == 0) {
        ret = a64_hook_validate_state();
    } else if (strncmp(cmd, "hook ", 5) == 0) {
        /* hook <function_name> */
        char *sym = cmd + 5;
        struct a64_hook_counter *counter;

        while (*sym == ' ') sym++;
        if (!*sym)
            return -EINVAL;

        counter = kzalloc(sizeof(*counter), GFP_KERNEL);
        if (!counter)
            return -ENOMEM;

        strscpy(counter->func_name, sym, sizeof(counter->func_name));
        atomic64_set(&counter->hits, 0);

        ret = a64_hook_install_by_name(sym, sym,
                    a64_hook_default_handler, counter,
                    A64_HOOK_DEFAULT_FLAGS);
        if (ret < 0) {
            kfree(counter);
            return ret;
        }
    } else if (strncmp(cmd, "kprobe ", 7) == 0) {
        /* kprobe <function_name> - force kprobe-based hooking */
        char *sym = cmd + 7;
        struct a64_hook_counter *counter;

        while (*sym == ' ') sym++;
        if (!*sym)
            return -EINVAL;

        counter = kzalloc(sizeof(*counter), GFP_KERNEL);
        if (!counter)
            return -ENOMEM;

        strscpy(counter->func_name, sym, sizeof(counter->func_name));
        atomic64_set(&counter->hits, 0);

        ret = a64_hook_install_by_name(sym, sym,
                    a64_hook_default_handler, counter,
                    A64_HOOK_DEFAULT_FLAGS | A64_HOOK_F_KPROBE);
        if (ret < 0) {
            kfree(counter);
            return ret;
        }
    } else if (strncmp(cmd, "unhook ", 7) == 0) {
        /* unhook <name|function_name> */
        char *sym = cmd + 7;
        struct a64_hook *hook;
        void *priv;

        while (*sym == ' ') sym++;
        if (!*sym)
            return -EINVAL;

        hook = a64_hook_find(sym);
        pr_info("a64_hook_dbg: unhook find '%s' -> %p\n", sym, hook);
        if (!hook) {
            ret = a64_hook_lookup(sym, &hook);
            pr_info("a64_hook_dbg: unhook lookup '%s' -> ret=%d hook=%p\n", sym, ret, hook);
            if (ret < 0 || !hook)
                return -ENOENT;
        }
        priv = hook->priv;
        a64_hook_remove(hook);
        pr_info("a64_hook_dbg: unhook remove done, kfree priv=%p\n", priv);
        kfree(priv);
    }

    return len;
}

static bool a64_is_hyp_available(void)
{
    if (a64_sym.boot_cpu_mode && a64_sym.kvm_protected_mode_initialized) {
        if (*a64_sym.kvm_protected_mode_initialized)
            return true;
        return a64_sym.boot_cpu_mode[0] == 0xe12 &&
               a64_sym.boot_cpu_mode[1] == 0xe12;
    }
    return false;
}

static int a64_hook_init_internal(void)
{
    int ret, cpu;

    /* Resolve symbols */
    ret = a64_sym_resolver_init();
    if (ret)
        return ret;

    a64_hook_verbose = verbose;
    a64_hook_debug = debug;
    a64_hook_max_hooks = max_hooks;
    a64_hook_use_kprobes = use_kprobes;
    a64_hook_use_dma = use_dma;
    a64_hook_use_stop_machine = use_stop_machine;

    spin_lock_init(&a64_hook_list_lock);
    atomic_set(&a64_hook_count_atomic, 0);
    atomic_set(&a64_hook_enabled_count, 0);
    memset(&a64_hook_stats, 0, sizeof(a64_hook_stats));
    a64_hook_stats.started_at = get_jiffies_64();

    a64_hook_percpu_stats = alloc_percpu(struct a64_hook_percpu);
    if (!a64_hook_percpu_stats)
        return -ENOMEM;

    for_each_possible_cpu(cpu) {
        struct a64_hook_percpu *pcpu;
        pcpu = per_cpu_ptr(a64_hook_percpu_stats, cpu);
        memset(pcpu, 0, sizeof(*pcpu));
    }

    a64_hook_cache = kmem_cache_create("a64_hook",
        sizeof(struct a64_hook), 0, SLAB_PANIC, NULL);
    if (!a64_hook_cache)
        goto err_percpu;

    a64_tramp_cache = kmem_cache_create("a64_tramp",
        sizeof(struct a64_trampoline), 0, SLAB_PANIC, NULL);
    if (!a64_tramp_cache)
        goto err_hook_cache;

    a64_kprobe_cache = kmem_cache_create("a64_kprobe",
        sizeof(struct a64_kprobe_entry), 0, SLAB_PANIC, NULL);
    if (!a64_kprobe_cache)
        goto err_tramp_cache;

    a64_dma_cache = kmem_cache_create("a64_dma",
        sizeof(struct a64_dma_mapping), 0, SLAB_PANIC, NULL);
    if (!a64_dma_cache)
        goto err_kprobe_cache;

    return 0;

err_kprobe_cache:
    kmem_cache_destroy(a64_kprobe_cache);
err_tramp_cache:
    kmem_cache_destroy(a64_tramp_cache);
err_hook_cache:
    kmem_cache_destroy(a64_hook_cache);
err_percpu:
    free_percpu(a64_hook_percpu_stats);
    return -ENOMEM;
}

static void a64_hook_cleanup_internal(void)
{
    struct a64_hook *hook, *tmp;
    unsigned long flags;

    /* Remove all hooks */
    spin_lock_irqsave(&a64_hook_list_lock, flags);
    list_for_each_entry_safe(hook, tmp, &a64_hook_list, list) {
        list_del(&hook->list);
        spin_unlock_irqrestore(&a64_hook_list_lock, flags);
        if (hook->state == A64_HOOK_STATE_ENABLED)
            a64_hook_uninstall(hook);
        a64_hook_free(hook);
        spin_lock_irqsave(&a64_hook_list_lock, flags);
    }
    spin_unlock_irqrestore(&a64_hook_list_lock, flags);

    kmem_cache_destroy(a64_dma_cache);
    kmem_cache_destroy(a64_kprobe_cache);
    kmem_cache_destroy(a64_tramp_cache);
    kmem_cache_destroy(a64_hook_cache);
    free_percpu(a64_hook_percpu_stats);
}

/*
 * Lifecycle: called by kernel via module_exit on rmmod.
 * Since module_init never runs on BlueStacks, this is the real entry point.
 * After init, blocks until "exit" command is sent via /proc.
 */
static int __init a64_hook_lifecycle(void)
{
    int ret;

    pr_emerg("a64_hook: lifecycle START\n");
    ret = a64_hook_init_internal();
    if (ret) {
        pr_emerg("a64_hook: init_internal failed %d\n", ret);
        return ret;
    }
    pr_emerg("a64_hook: step1 OK\n");

    ret = misc_register(&a64_hook_misc);
    if (ret) {
        pr_emerg("a64_hook: misc_register failed %d\n", ret);
        a64_hook_cleanup_internal();
        return ret;
    }
    pr_emerg("a64_hook: step2 OK\n");

    a64_hook_proc_entry = proc_create("a64_hook", 0666, NULL,
                                      &a64_hook_cmd_fops);
    if (!a64_hook_proc_entry) {
        pr_emerg("a64_hook: proc_create failed\n");
        misc_deregister(&a64_hook_misc);
        a64_hook_cleanup_internal();
        return -ENOMEM;
    }
    pr_emerg("a64_hook: step3 OK\n");

    pr_emerg("a64_hook: lifecycle DONE (stub - no GUI/vfb)\n");
    return 0;
}

static void a64_hook_work(struct work_struct *work)
{
    pr_emerg("a64_hook_work: running (1s after module load)\n");
    a64_hook_proc_entry = proc_create("a64_hook", 0666, NULL,
                                      &a64_hook_cmd_fops);
    if (a64_hook_proc_entry)
        pr_emerg("a64_hook_work: proc entry created\n");
    else
        pr_emerg("a64_hook_work: proc_create FAILED\n");
}
static DECLARE_DELAYED_WORK(a64_hook_dwork, a64_hook_work);

static int __init a64_minimal_init(void)
{
    pr_emerg("a64_minimal: init called, scheduling work\n");
    schedule_delayed_work(&a64_hook_dwork, HZ); /* 1 second */
    pr_emerg("a64_minimal: init done, returning 0\n");
    return 0;
}

module_init(a64_minimal_init);

static void __exit a64_hook_cleanup(void)
{
    pr_emerg("a64_hook: cleanup\n");
    a64_win_exit();
    a64_gui_exit();
    a64_vfb_exit();
    remove_proc_entry("a64_hook", NULL);
    misc_deregister(&a64_hook_misc);
    a64_hook_cleanup_internal();
}

module_exit(a64_hook_cleanup);
