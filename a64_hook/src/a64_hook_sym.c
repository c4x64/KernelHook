#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "a64_hook.h"
#include "a64_hook_sym.h"

struct a64_sym_resolver a64_sym;

static unsigned long sym_from_proc(const char *sym_name)
{
    struct file *f;
    char *buf, *p;
    unsigned long addr = 0;
    loff_t pos = 0;
    int ret;

    f = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(f))
        return 0;

    buf = kmalloc(32768, GFP_KERNEL);
    if (!buf) {
        filp_close(f, NULL);
        return 0;
    }

    ret = kernel_read(f, buf, 32767, &pos);
    filp_close(f, NULL);
    if (ret <= 0)
        goto out;
    buf[ret] = 0;

    p = buf;
    while (p && *p) {
        char name[128] = {0};
        char type;
        unsigned long val;

        if (sscanf(p, "%lx %c %127s", &val, &type, name) >= 3) {
            if (strcmp(name, sym_name) == 0) {
                addr = val;
                goto out;
            }
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
out:
    kfree(buf);
    return addr;
}

static void resolve_one(const char *name, unsigned long *target)
{
    unsigned long addr;

    addr = sym_from_proc(name);
    if (addr)
        *target = addr;
}

int a64_sym_resolver_init(void)
{
    resolve_one("kallsyms_lookup_name",
                (unsigned long *)&a64_sym.kallsyms_lookup_name);
    resolve_one("__module_address",
                (unsigned long *)&a64_sym.module_address);
    resolve_one("set_memory_rw",
                (unsigned long *)&a64_sym.set_memory_rw);
    resolve_one("set_memory_ro",
                (unsigned long *)&a64_sym.set_memory_ro);
    resolve_one("set_memory_x",
                (unsigned long *)&a64_sym.set_memory_x);
    resolve_one("module_alloc",
                (unsigned long *)&a64_sym.module_alloc);
    resolve_one("vfree",
                (unsigned long *)&a64_sym.vfree);
    resolve_one("aarch64_insn_write",
                (unsigned long *)&a64_sym.aarch64_insn_write);
    resolve_one("__boot_cpu_mode",
                (unsigned long *)&a64_sym.boot_cpu_mode);
    resolve_one("kvm_protected_mode_initialized",
                (unsigned long *)&a64_sym.kvm_protected_mode_initialized);

    if (!a64_sym.kallsyms_lookup_name)
        pr_warn("a64_hook: kallsyms_lookup_name not found\n");
    if (!a64_sym.module_address)
        pr_warn("a64_hook: __module_address not found\n");

    a64_sym.resolved = true;
    pr_info("a64_hook: resolver activated\n");
    return 0;
}

void a64_sym_resolver_exit(void)
{
    memset(&a64_sym, 0, sizeof(a64_sym));
}
