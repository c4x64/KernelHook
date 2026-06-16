#ifndef __A64_HOOK_SYM_H
#define __A64_HOOK_SYM_H

#include <linux/types.h>

struct a64_sym_resolver {
    unsigned long (*kallsyms_lookup_name)(const char *name);
    struct module *(*module_address)(unsigned long addr);
    int (*set_memory_rw)(unsigned long addr, int numpages);
    int (*set_memory_ro)(unsigned long addr, int numpages);
    int (*set_memory_x)(unsigned long addr, int numpages);
    void *(*module_alloc)(unsigned long size);
    void (*vfree)(const void *addr);
    int (*aarch64_insn_write)(void *addr, u32 insn);

    u32 *boot_cpu_mode;
    bool *kvm_protected_mode_initialized;

    bool resolved;
};

extern struct a64_sym_resolver a64_sym;

int a64_sym_resolver_init(void);
void a64_sym_resolver_exit(void);

#endif
