#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include "a64_hook_sym.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("test");
MODULE_DESCRIPTION("Resolver-only test");

struct a64_sym_resolver a64_sym;

static unsigned long param_kallsyms_addr;
module_param(param_kallsyms_addr, ulong, 0444);
static unsigned long param_module_addr;
module_param(param_module_addr, ulong, 0444);
static unsigned long param_set_mem_rw;
module_param(param_set_mem_rw, ulong, 0444);
static unsigned long param_boot_cpu_mode;
module_param(param_boot_cpu_mode, ulong, 0444);
static unsigned long param_kvm_protected;
module_param(param_kvm_protected, ulong, 0444);

static int __init test_init(void) {
    pr_info("test_resolver: start\n");
    memset(&a64_sym, 0, sizeof(a64_sym));
    if (param_kallsyms_addr) {
        a64_sym.kallsyms_lookup_name = (void *)param_kallsyms_addr;
        pr_info("test_resolver: kallsyms=0x%lx\n", param_kallsyms_addr);
    }
    if (param_module_addr) {
        a64_sym.module_address = (void *)param_module_addr;
        pr_info("test_resolver: modaddr=0x%lx\n", param_module_addr);
    }
    if (param_set_mem_rw) {
        a64_sym.set_memory_rw = (void *)param_set_mem_rw;
        pr_info("test_resolver: setmem=0x%lx\n", param_set_mem_rw);
    }
    if (param_boot_cpu_mode) {
        a64_sym.boot_cpu_mode = (u32 *)param_boot_cpu_mode;
        pr_info("test_resolver: bootcpu=0x%lx\n", param_boot_cpu_mode);
    }
    if (param_kvm_protected) {
        a64_sym.kvm_protected_mode_initialized = (bool *)param_kvm_protected;
        pr_info("test_resolver: kvm=0x%lx\n", param_kvm_protected);
    }
    /* Try dereferencing the data pointers */
    if (a64_sym.boot_cpu_mode && a64_sym.kvm_protected_mode_initialized) {
        pr_info("test_resolver: kvm_init=%d\n", *a64_sym.kvm_protected_mode_initialized);
        pr_info("test_resolver: boot_cpu_mode[0]=0x%x\n", a64_sym.boot_cpu_mode[0]);
    }
    pr_info("test_resolver: done\n");
    return 0;
}
module_init(test_init);

static void __exit test_exit(void) {
    memset(&a64_sym, 0, sizeof(a64_sym));
    pr_info("test_resolver: exit\n");
}
module_exit(test_exit);
