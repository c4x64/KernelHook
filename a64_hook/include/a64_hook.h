/*
 * a64_hook.h - ARM64 (AArch64) Inline Hook Engine
 *
 * A kernel module for ARM64 inline hooking using DMA-based physical memory
 * writes. Provides a complete alternative to A64Inlinehook with support for
 * detours, trampolines, kprobe fallback, and BPF program attachment.
 *
 * Author: a64-hook project
 * License: GPL v2
 */

#ifndef _A64_HOOK_H
#define _A64_HOOK_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/bpf.h>

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/cache.h>
#include <linux/compiler.h>
#include <linux/kprobes.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t s32;
typedef int64_t s64;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint8_t u8;
typedef int8_t s8;
typedef uintptr_t phys_addr_t;
typedef uintptr_t dma_addr_t;
struct list_head { struct list_head *next, *prev; };
struct hlist_node { struct hlist_node *next, **pprev; };
struct rcu_head { struct rcu_head *next; struct rcu_head **pprev; };
struct completion { unsigned int done; };
struct pt_regs { unsigned long regs[31]; unsigned long sp; unsigned long pc; unsigned long pstate; };
struct bpf_prog { int dummy; };
struct device { void *dummy; };
struct kprobe { void *addr; const char *symbol_name; };
struct kretprobe { struct kprobe kp; int maxactive; void *handler; void *entry_handler; };
struct kretprobe_instance { struct kretprobe *rp; };
struct kmem_cache { unsigned int size; };
struct dentry { void *dummy; };
struct seq_file { void *private; };
struct file { void *private_data; };
struct inode { void *i_private; };
typedef struct { int counter; } atomic_t;
#define spinlock_t int
#define GFP_KERNEL 0
#define __percpu
#define THIS_MODULE 0
static inline void spin_lock_init(int *l) { *l = 0; }
#define spin_lock(l) do { (void)(l); } while(0)
#define spin_unlock(l) do { (void)(l); } while(0)
#define spin_lock_irqsave(l, f) do { (void)(l); (f) = 0; } while(0)
#define spin_unlock_irqrestore(l, f) do { (void)(l); (void)(f); } while(0)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define cache_line_size() 64
#define dsb(opt) __asm__ volatile("dsb " #opt : : : "memory")
#define isb() __asm__ volatile("isb" : : : "memory")
#include <stdlib.h>
#include <stdio.h>
#define pr_err(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

#define A64_INSN_SIZE 4

/*
 * Version information
 */
#define A64_HOOK_VERSION_MAJOR      2
#define A64_HOOK_VERSION_MINOR      1
#define A64_HOOK_VERSION_PATCH      0
#define A64_HOOK_VERSION_STRING     "2.1.0"

/*
 * Maximum sizes and limits
 */
#define A64_HOOK_MAX_NAME           64
#define A64_HOOK_MAX_HOOKS          4096
#define A64_HOOK_MAX_TRAMPOLINE     128
#define A64_HOOK_MAX_INSN_SIZE      16
#define A64_HOOK_BRANCH_RANGE       (1 << 27)
#define A64_HOOK_TEMP_INSN_MAX      16
#define A64_HOOK_STACK_FRAME_MAX    256
#define A64_HOOK_MODULE_NAME_LEN    64
#define A64_HOOK_SYMBOL_NAME_LEN    256
#define A64_HOOK_TRAMPOLINE_MAX     32
#define A64_HOOK_TRAMPOLINE_MAX_INSN 16

/*
 * Error codes
 */
#define A64_HOOK_SUCCESS            0
#define A64_HOOK_ERR_NOMEM          1
#define A64_HOOK_ERR_INVAL          2
#define A64_HOOK_ERR_NOSYM          3
#define A64_HOOK_ERR_HOOK_EXISTS    4
#define A64_HOOK_ERR_HOOK_NOTFOUND  5
#define A64_HOOK_ERR_TOO_MANY       6
#define A64_HOOK_ERR_BRANCH_OUT     7
#define A64_HOOK_ERR_UNSUPPORTED    8
#define A64_HOOK_ERR_BUSY           9
#define A64_HOOK_ERR_PERM           10
#define A64_HOOK_ERR_DMA            11
#define A64_HOOK_ERR_KPROBE         12
#define A64_HOOK_ERR_DISABLED       13
#define A64_HOOK_ERR_CORRUPT        14

/*
 * Hook flags
 */
#define A64_HOOK_F_NONE             (0ULL)
#define A64_HOOK_F_KPROBE           (1ULL << 0)
#define A64_HOOK_F_ATOMIC           (1ULL << 1)
#define A64_HOOK_F_DMA              (1ULL << 2)
#define A64_HOOK_F_BPF              (1ULL << 3)
#define A64_HOOK_F_TRAMPOLINE       (1ULL << 4)
#define A64_HOOK_F_STEALTH          (1ULL << 5)
#define A64_HOOK_F_NO_SYNC          (1ULL << 6)
#define A64_HOOK_F_PREEMPT_SAFE     (1ULL << 7)
#define A64_HOOK_F_IRQ_SAFE         (1ULL << 8)
#define A64_HOOK_F_RECURSIVE        (1ULL << 9)
#define A64_HOOK_F_DYNAMIC          (1ULL << 10)
#define A64_HOOK_F_PERMANENT        (1ULL << 11)
#define A64_HOOK_F_REENTRANT        (1ULL << 12)
#define A64_HOOK_F_FASTPATH         (1ULL << 13)
#define A64_HOOK_F_DEBUG            (1ULL << 14)
#define A64_HOOK_F_PERCPU           (1ULL << 15)
#define A64_HOOK_F_SMP              (1ULL << 16)

/*
 * Hook type
 */
enum a64_hook_type {
    A64_HOOK_TYPE_INLINE      = 0,
    A64_HOOK_TYPE_DETOUR      = 1,
    A64_HOOK_TYPE_KPROBE      = 2,
    A64_HOOK_TYPE_BL           = 3,
    A64_HOOK_TYPE_BR           = 4,
    A64_HOOK_TYPE_BLR          = 5,
    A64_HOOK_TYPE_RETPROBE     = 6,
    A64_HOOK_TYPE_FENTRY       = 7,
    A64_HOOK_TYPE_FEXIT        = 8,
    A64_HOOK_TYPE_DMA_ONLY     = 9,
    A64_HOOK_TYPE_MAX
};

/*
 * Hook state
 */
enum a64_hook_state {
    A64_HOOK_STATE_DISABLED   = 0,
    A64_HOOK_STATE_ENABLED    = 1,
    A64_HOOK_STATE_PENDING    = 2,
    A64_HOOK_STATE_ERROR      = 3,
    A64_HOOK_STATE_REMOVING   = 4,
    A64_HOOK_STATE_RESUMED    = 5,
};

/*
 * Hook handler prototype
 */
typedef int (*a64_hook_handler_t)(struct pt_regs *regs, void *priv);

/*
 * Trampoline handler prototype (called from generated trampoline)
 */
typedef void (*a64_trampoline_handler_t)(struct pt_regs *regs, void *priv);

/*
 * BPF program attachment descriptor
 */
struct a64_hook_bpf_ctx {
    struct bpf_prog          *prog;
    char                     name[A64_HOOK_MAX_NAME];
    u64                      flags;
    u64                      start_time;
    u64                      call_count;
    u64                      total_ns;
};

/*
 * Per-hook statistics
 */
struct a64_hook_stats {
    u64                      hits;
    u64                      misses;
    u64                      dma_writes;
    u64                      bytes_written;
    u64                      cache_flushes;
    u64                      tramp_calls;
    u64                      errors;
    u64                      kprobe_fallbacks;
    u64                      preempt_disable_count;
    u64                      irq_disable_count;
    u64                      total_latency_ns;
    u64                      avg_latency_ns;
    u64                      max_latency_ns;
    u64                      min_latency_ns;
    u64                      installed_at_jiffies;
    u64                      last_fired_jiffies;
    u64                      bpf_attached;
    u64                      insn_count;
};

/*
 * DMA mapping descriptor for physical memory writes
 */
struct a64_dma_mapping {
    phys_addr_t              phys_addr;
    void                     *virt_addr;
    size_t                   size;
    dma_addr_t               dma_handle;
    u32                      flags;
    bool                     coherent;
    bool                     mapped;
    struct device            *dev;
    u64                      write_count;
    u64                      write_bytes;
    spinlock_t               lock;
};

/*
 * Saved original instruction(s)
 */
struct a64_hook_insn {
    u32                      insn;
    u32                      mask;
    unsigned long            pc;
    int                      size;
    int                      index;
    u16                      regs_read;
    u16                      regs_written;
    bool                     is_branch;
    bool                     is_call;
    bool                     is_ret;
    bool                     is_indirect;
    bool                     is_ldr;
    bool                     is_str;
    bool                     is_nop;
    bool                     is_brk;
    bool                     is_pc_rel;
    bool                     is_adr;
    bool                     is_adrp;
    bool                     is_ldr_literal;
    bool                     is_add;
    bool                     is_sub;
    bool                     is_and;
    bool                     is_orr;
    bool                     is_eor;
    bool                     is_mov;
    bool                     is_mul;
    bool                     is_shift;
    bool                     is_fp;
    bool                     is_simd;
    bool                     is_sve;
    bool                     is_pac;
    bool                     is_system;
    bool                     is_smc;
    bool                     is_cvt;
    bool                     is_bic;
    bool                     is_orn;
    bool                     is_eon;
    long long                target_offset;
    union {
        struct {
            u8               rd;
            u8               rn;
            u8               rm;
            u8              ra;
        } reg;
        struct {
            u8               rt;
            u8               rn;
            s16              imm;
        } ldr;
        struct {
            u8               rt;
            s64              imm;
        } adrp;
        struct {
            u8               cond;
            s64              offset;
        } branch;
    };
};

/*
 * Trampoline context
 */
struct a64_trampoline {
    u32                      *code;
    size_t                   size;
    unsigned long            pc;
    int                      n_insns;
    bool                     allocated;
    bool                     in_use;
    bool                     needs_epilogue;
    u32                      epilogue[4];
    struct a64_hook_insn     saved_insns[A64_HOOK_TRAMPOLINE_MAX_INSN];
    int                      n_saved;
    u8                       reg_save_mask;
    u8                       reg_restore_mask;
    spinlock_t               lock;
};

/*
 * Kprobe fallback descriptor
 */
struct a64_kprobe_entry {
    struct kprobe            kp;
    struct kretprobe         rp;
    a64_hook_handler_t       pre_handler;
    a64_hook_handler_t       post_handler;
    a64_hook_handler_t       fault_handler;
    void                     *priv;
    bool                     is_kretprobe;
    bool                     registered;
    char                     sym_name[A64_HOOK_SYMBOL_NAME_LEN];
    unsigned long            addr;
    spinlock_t               lock;
};

/*
 * The main hook descriptor structure
 */
struct a64_hook {
    char                     name[A64_HOOK_MAX_NAME];
    unsigned long             target_addr;
    unsigned long             handler_addr;
    void                     *priv;
    enum a64_hook_type       type;
    enum a64_hook_state      state;
    u64                      flags;
    int                      priority;

    struct a64_hook_insn     orig_insns[A64_HOOK_MAX_INSN_SIZE];
    int                      n_orig_insns;
    u32                      hook_insn;
    u32                      branch_back_insn;

    struct a64_trampoline    *trampoline;
    struct a64_hook_stats    stats;
    struct a64_dma_mapping   *dma_map;
    struct a64_kprobe_entry  *kprobe;

    struct a64_hook_bpf_ctx  *bpf_ctx;
    struct bpf_prog          *bpf_prog_orig;

    struct list_head         list;
    struct hlist_node        hash_node;
    spinlock_t               lock;
    struct rcu_head          rcu;

    u64                      create_time;
    u64                      modify_time;
    char                     module_name[A64_HOOK_MODULE_NAME_LEN];
    char                     sym_name[A64_HOOK_SYMBOL_NAME_LEN];
    unsigned long            sym_offset;
    int                      cpu;
    pid_t                    owner_pid;

    struct a64_hook         *next;
    struct a64_hook         *chain_prev;
    struct a64_hook         *chain_next;
    int                      chain_depth;
};

/*
 * Hook iterator
 */
struct a64_hook_iter {
    int                      index;
    struct a64_hook          *curr;
    u64                      filter_flags;
    enum a64_hook_type       filter_type;
    int                      filter_enabled;
    char                     filter_name[A64_HOOK_MAX_NAME];
};

/*
 * Hook chain node (for multiple hooks at same address)
 */
struct a64_hook_chain {
    struct a64_hook          *hooks[A64_HOOK_TRAMPOLINE_MAX];
    int                      n_hooks;
    unsigned long            target_addr;
    u64                      total_hits;
    u64                      total_latency;
    spinlock_t               lock;
};

/*
 * DMA transfer descriptor for physical memory writes
 */
struct a64_dma_transfer {
    phys_addr_t              target_paddr;
    void                     *source;
    size_t                   size;
    dma_addr_t               dma_src;
    dma_addr_t               dma_dst;
    struct completion        done;
    bool                     use_completion;
    int                      status;
    bool                     use_dma;
};

/*
 * Per-CPU hook state for safe preemption/IRQ handling
 */
struct a64_hook_percpu {
    u32                      depth;
    u32                      flags;
    bool                     in_hook;
    u64                      last_entry;
    u64                      last_exit;
    unsigned long             last_pc;
    struct a64_hook          *current_hook;
    struct pt_regs           saved_regs;
    u64                      call_count;
    u64                      total_ns;
};

/*
 * Global statistics
 */
struct a64_hook_global_stats {
    u64                      total_hooks;
    u64                      enabled_hooks;
    u64                      disabled_hooks;
    u64                      error_hooks;
    u64                      total_hits;
    u64                      total_dma_writes;
    u64                      total_bytes_written;
    u64                      total_cache_flushes;
    u64                      total_kprobe_fallbacks;
    u64                      total_trampolines;
    u64                      total_dma_mappings;
    u64                      total_errors;
    u64                      total_bpf_attachments;
    u64                      total_chain_hooks;
    u64                      max_chain_depth;
    u64                      total_latency_ns;
    u64                      peak_hook_count;
    u64                      oom_count;
    u64                      panic_count;
    u64                      started_at;
    u64                      uptime_jiffies;
    u64                      trampoline_pages;
    u64                      dma_pages;
    u64                      cache_line_flushes;
    u64                      stop_machine_calls;
};

/*
 * BIOS/EFI hook descriptor
 */
struct a64_hook_bios_entry {
    unsigned long            addr;
    char                     signature[16];
    u32                      length;
    u16                      type;
    u16                      attributes;
};

/*
 ===========================================================================
  Public API Functions
 ===========================================================================
 */

/*
 * Core hook management
 */
int  a64_hook_install(struct a64_hook *hook);
int  a64_hook_uninstall(struct a64_hook *hook);
int  a64_hook_enable(struct a64_hook *hook);
int  a64_hook_disable(struct a64_hook *hook);
void a64_hook_remove(struct a64_hook *hook);
int  a64_hook_install_by_name(const char *name, const char *target_sym,
                              a64_hook_handler_t handler, void *priv,
                              u64 flags);

/*
 * Hook creation helpers
 */
struct a64_hook *a64_hook_alloc(void);
void a64_hook_free(struct a64_hook *hook);
int  a64_hook_init(struct a64_hook *hook, const char *name,
                   unsigned long target, unsigned long handler,
                   enum a64_hook_type type, u64 flags);
int  a64_hook_init_sym(struct a64_hook *hook, const char *name,
                       const char *target_sym, unsigned long handler,
                       enum a64_hook_type type, u64 flags);

/*
 * Hook query / iteration
 */
struct a64_hook *a64_hook_find(const char *name);
struct a64_hook *a64_hook_find_by_addr(unsigned long addr);
int  a64_hook_lookup(const char *name, struct a64_hook **out);
int  a64_hook_iter_start(struct a64_hook_iter *iter);
struct a64_hook *a64_hook_iter_next(struct a64_hook_iter *iter);
void a64_hook_iter_end(struct a64_hook_iter *iter);
int  a64_hook_count(void);
int  a64_hook_get_stats(struct a64_hook_global_stats *stats);

/*
 * DMA operations
 */
int  a64_dma_init(struct a64_dma_mapping *dma, struct device *dev,
                  size_t size);
void a64_dma_exit(struct a64_dma_mapping *dma);
int  a64_dma_write_phys(phys_addr_t paddr, const void *data, size_t size);
int  a64_dma_write_virt(unsigned long vaddr, const void *data, size_t size);
int  a64_dma_patch_text(unsigned long addr, u32 insn);
int  a64_dma_patch_text_batch(unsigned long addr, const u32 *insns, int n);
int  a64_dma_sync(struct a64_dma_mapping *dma);
void a64_dma_flush_icache(unsigned long addr, size_t size);
int  a64_dma_map_target(unsigned long vaddr, struct a64_dma_mapping *dma);
void a64_dma_unmap_target(struct a64_dma_mapping *dma);
int  a64_dma_transfer(struct a64_dma_transfer *xfer);
phys_addr_t a64_virt_to_phys(volatile void *addr);
void *a64_phys_to_virt(phys_addr_t addr);

/*
 * ARM64 instruction patching
 */
int  a64_patch_insn(unsigned long addr, u32 insn);
int  a64_patch_insn_smp(unsigned long addr, u32 insn);
int  a64_patch_branch(unsigned long addr, unsigned long target);
int  a64_patch_bl(unsigned long addr, unsigned long target);
int  a64_patch_nop(unsigned long addr);
int  a64_patch_brk(unsigned long addr, u16 imm);
int  a64_patch_movn(unsigned long addr, u64 val, int shift);
int  a64_patch_ldr_literal(unsigned long addr, unsigned long target);
int  a64_check_patch_range(unsigned long from, unsigned long to);

/*
 * Trampoline operations
 */
int  a64_tramp_alloc(struct a64_trampoline *tramp, int n_slots);
void a64_tramp_free(struct a64_trampoline *tramp);
int  a64_tramp_generate(struct a64_trampoline *tramp,
                        const struct a64_hook_insn *insns, int n_insns,
                        unsigned long handler_addr, unsigned long priv,
                        unsigned long return_addr);
int  a64_tramp_install(struct a64_trampoline *tramp, unsigned long at);
void a64_tramp_remove(struct a64_trampoline *tramp);
unsigned long a64_tramp_entry(struct a64_trampoline *tramp);

/*
 * Kprobe fallback
 */
int  a64_kprobe_register(struct a64_kprobe_entry *entry);
int  a64_kprobe_unregister(struct a64_kprobe_entry *entry);
int  a64_kprobe_install(struct a64_hook *hook);
int  a64_kprobe_remove(struct a64_hook *hook);
int  a64_kprobe_enable(struct a64_kprobe_entry *entry);
int  a64_kprobe_disable(struct a64_kprobe_entry *entry);
bool a64_kprobe_available(void);

/*
 * BPF attachment
 */
int  a64_hook_attach_bpf(struct a64_hook *hook, struct bpf_prog *prog);
int  a64_hook_detach_bpf(struct a64_hook *hook);
int  a64_hook_run_bpf(struct a64_hook *hook, struct pt_regs *regs);

/*
 * Hook chaining
 */
int  a64_hook_chain_add(struct a64_hook_chain *chain, struct a64_hook *hook);
int  a64_hook_chain_remove(struct a64_hook_chain *chain, struct a64_hook *hook);
int  a64_hook_chain_execute(struct a64_hook_chain *chain, struct pt_regs *regs);
struct a64_hook_chain *a64_hook_chain_find(unsigned long addr);

/*
 * Debug / introspection
 */
void a64_hook_show(struct a64_hook *hook, char *buf, size_t size);
void a64_hook_show_all(char *buf, size_t size);
void a64_hook_dump_stats(struct a64_hook *hook);
int  a64_hook_self_test(void);
int  a64_hook_validate(struct a64_hook *hook);
int  a64_hook_validate_state(void);

/*
 * Module init / exit (called by module entry point)
 */
int  a64_hook_module_init(void);
void a64_hook_module_exit(void);

/*
 * Atomic patching helpers (stop_machine based)
 */
struct a64_patch_work {
    unsigned long            addr;
    u32                      insn;
    u32                      old_insn;
    int                      result;
    int                      n_patches;
    unsigned long            *addrs;
    u32                      *insns;
    u32                      *old_insns;
    struct completion        done;
    bool                     use_completion;
};

int  a64_atomic_patch(struct a64_patch_work *work);
int  a64_atomic_patch_single(unsigned long addr, u32 insn, u32 *old);
int  a64_atomic_patch_multi(unsigned long *addrs, u32 *insns, int n);

/*
 ===========================================================================
  ARM64 Instruction Encoding Helpers
 ===========================================================================
 */

/* Branch instruction encoding */
u32 a64_insn_b(unsigned long pc, unsigned long target);
u32 a64_insn_bl(unsigned long pc, unsigned long target);
u32 a64_insn_bcond(unsigned long pc, unsigned long target, u8 cond);
u32 a64_insn_cbz(unsigned long pc, unsigned long target, u8 rt, bool is64);
u32 a64_insn_tbz(unsigned long pc, unsigned long target, u8 rt, u8 bit,
                  bool is_positive);
u32 a64_insn_br(u8 rn);
u32 a64_insn_blr(u8 rn);
u32 a64_insn_ret(u8 rn);
u32 a64_insn_nop(void);
u32 a64_insn_brk(u16 imm);

/* Data processing */
u32 a64_insn_movn(u8 rd, u16 imm, int shift);
u32 a64_insn_movz(u8 rd, u16 imm, int shift);
u32 a64_insn_movk(u8 rd, u16 imm, int shift);
u32 a64_insn_add_imm(u8 rd, u8 rn, u16 imm12, int shift);
u32 a64_insn_sub_imm(u8 rd, u8 rn, u16 imm12, int shift);
u32 a64_insn_add_reg(u8 rd, u8 rn, u8 rm, int shift);
u32 a64_insn_sub_reg(u8 rd, u8 rn, u8 rm, int shift);

/* Logical */
u32 a64_insn_and_imm(u8 rd, u8 rn, u64 imm, bool is64);
u32 a64_insn_orr_imm(u8 rd, u8 rn, u64 imm, bool is64);
u32 a64_insn_eor_imm(u8 rd, u8 rn, u64 imm, bool is64);
u32 a64_insn_and_reg(u8 rd, u8 rn, u8 rm);
u32 a64_insn_orr_reg(u8 rd, u8 rn, u8 rm);
u32 a64_insn_eor_reg(u8 rd, u8 rn, u8 rm);
u32 a64_insn_mov_reg(u8 rd, u8 rm);
u32 a64_insn_madd(u8 rd, u8 rn, u8 rm, u8 ra);
u32 a64_insn_msub(u8 rd, u8 rn, u8 rm, u8 ra);
u32 a64_insn_cmp_imm(u8 rn, u16 imm12, int shift);
u32 a64_insn_cmn_imm(u8 rn, u16 imm12, int shift);
u32 a64_insn_cmp_reg(u8 rn, u8 rm);
u32 a64_insn_cmn_reg(u8 rn, u8 rm);
u32 a64_insn_csel(u8 rd, u8 rn, u8 rm, u8 cond);
u32 a64_insn_csinc(u8 rd, u8 rn, u8 rm, u8 cond);
u32 a64_insn_csinv(u8 rd, u8 rn, u8 rm, u8 cond);
u32 a64_insn_csneg(u8 rd, u8 rn, u8 rm, u8 cond);
u32 a64_insn_mul(u8 rd, u8 rn, u8 rm);
u32 a64_insn_mneg(u8 rd, u8 rn, u8 rm);
u32 a64_insn_cbnz(unsigned long pc, unsigned long target, u8 rt, bool is64);
u32 a64_insn_ccmp_imm(u8 rn, u8 imm5, u8 nzcv, u8 cond);
u32 a64_insn_ccmp_reg(u8 rn, u8 rm, u8 nzcv, u8 cond);
u32 a64_insn_smull(u8 rd, u8 rn, u8 rm);
u32 a64_insn_umull(u8 rd, u8 rn, u8 rm);
u32 a64_insn_sdiv(u8 rd, u8 rn, u8 rm);
u32 a64_insn_udiv(u8 rd, u8 rn, u8 rm);
u32 a64_insn_lslv(u8 rd, u8 rn, u8 rm);
u32 a64_insn_lsrv(u8 rd, u8 rn, u8 rm);
u32 a64_insn_asrv(u8 rd, u8 rn, u8 rm);
u32 a64_insn_rorv(u8 rd, u8 rn, u8 rm);

/* Load/store */
u32 a64_insn_ldr_imm(u8 rt, u8 rn, s16 imm, int size);
u32 a64_insn_str_imm(u8 rt, u8 rn, s16 imm, int size);
u32 a64_insn_ldp(u8 rt1, u8 rt2, u8 rn, s16 imm, int size);
u32 a64_insn_stp(u8 rt1, u8 rt2, u8 rn, s16 imm, int size);
u32 a64_insn_ldr_literal(unsigned long pc, unsigned long target, u8 rt);
u32 a64_insn_ldr_reg(u8 rt, u8 rn, u8 rm, int opt, int shift);
u32 a64_insn_str_reg(u8 rt, u8 rn, u8 rm, int opt, int shift);

/* System registers */
u32 a64_insn_msr(const char *reg, u8 rt);
u32 a64_insn_mrs(const char *reg, u8 rt);
u32 a64_insn_dmb(u32 barrier);
u32 a64_insn_dsb(u32 barrier);
u32 a64_insn_isb(void);

/* Cache maintenance */
u32 a64_insn_ic_ivau(u8 rt);
u32 a64_insn_dc_cvac(u8 rt);
u32 a64_insn_dc_cvau(u8 rt);
u32 a64_insn_dc_civac(u8 rt);
u32 a64_insn_dc_zva(u8 rt);
u32 a64_insn_clrex(u8 imm4);
u32 a64_insn_ldrb_imm(u8 rt, u8 rn, u16 imm12);
u32 a64_insn_strb_imm(u8 rt, u8 rn, u16 imm12);
u32 a64_insn_ldrh_imm(u8 rt, u8 rn, u16 imm12);
u32 a64_insn_strh_imm(u8 rt, u8 rn, u16 imm12);
u32 a64_insn_ldrsw_imm(u8 rt, u8 rn, u16 imm12);
u32 a64_insn_adr(unsigned long pc, unsigned long target, u8 rd);
u32 a64_insn_adrp(unsigned long pc, unsigned long target, u8 rd);
u32 a64_insn_sxtb(u8 rd, u8 rn);
u32 a64_insn_sxth(u8 rd, u8 rn);
u32 a64_insn_sxtw(u8 rd, u8 rn);
u32 a64_insn_uxtb(u8 rd, u8 rn);
u32 a64_insn_uxth(u8 rd, u8 rn);
u32 a64_insn_tst_imm(u8 rn, u64 imm, bool is64);
u32 a64_insn_ldp_pre(u8 rt1, u8 rt2, u8 rn, s16 imm, int size);
u32 a64_insn_stp_pre(u8 rt1, u8 rt2, u8 rn, s16 imm, int size);
u32 a64_insn_ldp_post(u8 rt1, u8 rt2, u8 rn, s16 imm, int size);
u32 a64_insn_stp_post(u8 rt1, u8 rt2, u8 rn, s16 imm, int size);
u32 a64_insn_ldur(u8 rt, u8 rn, s16 imm, int size);
u32 a64_insn_stur(u8 rt, u8 rn, s16 imm, int size);
u32 a64_insn_ldr_reg(u8 rt, u8 rn, u8 rm, int opt, int shift);
u32 a64_insn_str_reg(u8 rt, u8 rn, u8 rm, int opt, int shift);
u32 a64_insn_bic_reg(u8 rd, u8 rn, u8 rm);
u32 a64_insn_orn_reg(u8 rd, u8 rn, u8 rm);
u32 a64_insn_eon_reg(u8 rd, u8 rn, u8 rm);
u32 a64_insn_mvn_reg(u8 rd, u8 rm);
u32 a64_insn_lsl_imm(u8 rd, u8 rn, u8 shift);
u32 a64_insn_lsr_imm(u8 rd, u8 rn, u8 shift);
u32 a64_insn_asr_imm(u8 rd, u8 rn, u8 shift);
u32 a64_insn_ror_imm(u8 rd, u8 rn, u8 shift);
u32 a64_insn_adds_imm(u8 rd, u8 rn, u16 imm12, int shift);
u32 a64_insn_subs_imm(u8 rd, u8 rn, u16 imm12, int shift);
u32 a64_insn_bti(u8 imm);
u32 a64_insn_bti_c(void);
u32 a64_insn_bti_j(void);
u32 a64_insn_bti_jc(void);
u32 a64_insn_esb(void);
u32 a64_insn_psb_csync(void);
u32 a64_insn_tsb_csync(void);
u32 a64_insn_csdb(void);
u32 a64_insn_pacia(u8 rd, u8 rn);
u32 a64_insn_pacib(u8 rd, u8 rn);
u32 a64_insn_pacda(u8 rd, u8 rn);
u32 a64_insn_pacdb(u8 rd, u8 rn);
u32 a64_insn_autia(u8 rd, u8 rn);
u32 a64_insn_autib(u8 rd, u8 rn);
u32 a64_insn_xpaci(u8 rd);
u32 a64_insn_xpacd(u8 rd);
u32 a64_insn_stg(u8 rt, u8 rn, s16 imm);
u32 a64_insn_ldg(u8 rt, u8 rn, s16 imm);
u32 a64_insn_stzgm(u8 rt, u8 rn);
u32 a64_insn_ldzm(u8 rt, u8 rn);
u32 a64_insn_addg(u8 rd, u8 rn, u16 imm6, u8 uimm4);
u32 a64_insn_subg(u8 rd, u8 rn, u16 imm6, u8 uimm4);
u32 a64_insn_irg(u8 rd, u8 rn, u8 rm);
u32 a64_insn_gmi(u8 rd, u8 rn, u8 rm);
u32 a64_insn_subp(u8 rd, u8 rn, u8 rm);
u32 a64_insn_fmov_fp2fp(u8 rd, u8 rn, int size);
u32 a64_insn_fmov_gp2fp(u8 rd, u8 rn, int size);
u32 a64_insn_fmov_fp2gp(u8 rd, u8 rn, int size);
u32 a64_insn_fadd_fp(u8 rd, u8 rn, u8 rm, int size);
u32 a64_insn_fsub_fp(u8 rd, u8 rn, u8 rm, int size);
u32 a64_insn_fmul_fp(u8 rd, u8 rn, u8 rm, int size);
u32 a64_insn_fdiv_fp(u8 rd, u8 rn, u8 rm, int size);
u32 a64_insn_fabs_fp(u8 rd, u8 rn, int size);
u32 a64_insn_fneg_fp(u8 rd, u8 rn, int size);
u32 a64_insn_fsqrt_fp(u8 rd, u8 rn, int size);
u32 a64_insn_fcmp_fp(u8 rn, u8 rm, int size);
u32 a64_insn_fcmpz_fp(u8 rn, int size);
u32 a64_insn_fcvt(u8 rd, u8 rn, int src_size, int dst_size);
u32 a64_insn_scvtf(u8 rd, u8 rn, int size);
u32 a64_insn_ucvtf(u8 rd, u8 rn, int size);
u32 a64_insn_fcvtzs(u8 rd, u8 rn, int size);
u32 a64_insn_fcvtpu(u8 rd, u8 rn, int size);
u32 a64_insn_fcvtau(u8 rd, u8 rn, int size);

/*
 ===========================================================================
  ARM64 Instruction Decoding Helpers
 ===========================================================================
 */

/* Decode an instruction and fill the hook_insn structure */
int  a64_decode_insn(u32 insn, struct a64_hook_insn *decoded);
int  a64_decode_insns(const u32 *insns, int n,
                      struct a64_hook_insn *decoded, int max);
int  a64_insn_length(u32 insn);
bool a64_insn_is_branch(u32 insn);
bool a64_insn_is_call(u32 insn);
bool a64_insn_is_ret(u32 insn);
bool a64_insn_is_ldr(u32 insn);
bool a64_insn_is_str(u32 insn);

/* Opcode database functions */
int  a64_opcode_lookup(u32 insn, char *mnemonic, size_t mnemonic_size);
int  a64_insn_arch_version(u32 insn);
bool a64_insn_is_supported(u32 insn, int arch_version);

/* Frame analysis */
struct a64_frame_info {
    int  frame_size;
    bool has_fp;
    bool has_lr;
    bool has_pac;
    int  saved_regs;
    u8   reg_save_list[16];
    int  n_regs_saved;
};
int a64_analyze_prologue(const u32 *insns, int n_insns,
                          struct a64_frame_info *info);
int a64_analyze_epilogue(const u32 *insns, int n_insns,
                          struct a64_frame_info *info);
bool a64_insn_is_pc_rel(u32 insn);
bool a64_insn_reads_reg(u32 insn, u8 reg);
bool a64_insn_writes_reg(u32 insn, u8 reg);
int  a64_insn_regs_read(u32 insn, u8 *regs, int max);
int  a64_insn_regs_written(u32 insn, u8 *regs, int max);
long long a64_insn_target_offset(u32 insn, unsigned long pc);

/* Find the minimum number of instructions to patch */
int  a64_find_hook_region(const u32 *code, int max_insns,
                          unsigned long target, unsigned long handler,
                          u32 *hook_insn);

/*
 ===========================================================================
  Convenience Macros
 ===========================================================================
 */

#define A64_HOOK_INIT(hook, name, target_addr, handler_addr, type, flags_) \
    do { \
        (hook)->name[0] = '\0'; \
        strscpy((hook)->name, name, sizeof((hook)->name)); \
        (hook)->target_addr = (unsigned long)(target_addr); \
        (hook)->handler_addr = (unsigned long)(handler_addr); \
        (hook)->type = (type); \
        (hook)->flags = (flags_); \
        (hook)->state = A64_HOOK_STATE_DISABLED; \
    } while (0)

#define a64_hook_for_each(pos) \
    list_for_each_entry(pos, &a64_hook_list, list)

#define a64_hook_for_each_safe(pos, tmp) \
    list_for_each_entry_safe(pos, tmp, &a64_hook_list, list)

/*
 * Conditional branch conditions (for B.cond)
 */
#define A64_COND_EQ    0x0
#define A64_COND_NE    0x1
#define A64_COND_CS    0x2
#define A64_COND_CC    0x3
#define A64_COND_MI    0x4
#define A64_COND_PL    0x5
#define A64_COND_VS    0x6
#define A64_COND_VC    0x7
#define A64_COND_HI    0x8
#define A64_COND_LS    0x9
#define A64_COND_GE    0xa
#define A64_COND_LT    0xb
#define A64_COND_GT    0xc
#define A64_COND_LE    0xd
#define A64_COND_AL    0xe
#define A64_COND_NV    0xf

/*
 * Barrier types
 */
#define A64_BARRIER_SY     0xf
#define A64_BARRIER_ST     0xe
#define A64_BARRIER_LD     0xd
#define A64_BARRIER_ISH    0xb
#define A64_BARRIER_ISHST  0xa
#define A64_BARRIER_ISHLD  0x9
#define A64_BARRIER_NSH    0x7
#define A64_BARRIER_NSHST  0x6
#define A64_BARRIER_NSHLD  0x5
#define A64_BARRIER_OSH    0x3
#define A64_BARRIER_OSHST  0x2
#define A64_BARRIER_OSHLD  0x1

/*
 * Default flags
 */
#define A64_HOOK_DEFAULT_FLAGS \
    (A64_HOOK_F_DMA | A64_HOOK_F_ATOMIC | A64_HOOK_F_PREEMPT_SAFE | \
     A64_HOOK_F_TRAMPOLINE)

/*
 * Helper: Install a simple detour hook
 */
#define a64_hook_simple(name, sym, handler) \
    a64_hook_install_by_name(name, sym, \
        (a64_hook_handler_t)(handler), NULL, A64_HOOK_DEFAULT_FLAGS)

/*
 * Helper: Install a kprobe-based hook
 */
#define a64_hook_kprobe(name, sym, handler) \
    a64_hook_install_by_name(name, sym, \
        (a64_hook_handler_t)(handler), NULL, \
        A64_HOOK_DEFAULT_FLAGS | A64_HOOK_F_KPROBE)

/*
 * Register save/restore bitmask for trampolines
 */
#define A64_TRAMP_SAVE_X0   (1 << 0)
#define A64_TRAMP_SAVE_X1   (1 << 1)
#define A64_TRAMP_SAVE_X2   (1 << 2)
#define A64_TRAMP_SAVE_X3   (1 << 3)
#define A64_TRAMP_SAVE_X4   (1 << 4)
#define A64_TRAMP_SAVE_X5   (1 << 5)
#define A64_TRAMP_SAVE_X6   (1 << 6)
#define A64_TRAMP_SAVE_X7   (1 << 7)
#define A64_TRAMP_SAVE_X8   (1 << 8)
#define A64_TRAMP_SAVE_X9   (1 << 9)
#define A64_TRAMP_SAVE_X10  (1 << 10)
#define A64_TRAMP_SAVE_X11  (1 << 11)
#define A64_TRAMP_SAVE_X12  (1 << 12)
#define A64_TRAMP_SAVE_X13  (1 << 13)
#define A64_TRAMP_SAVE_X14  (1 << 14)
#define A64_TRAMP_SAVE_X15  (1 << 15)
#define A64_TRAMP_SAVE_X16  (1 << 16)
#define A64_TRAMP_SAVE_X17  (1 << 17)
#define A64_TRAMP_SAVE_X18  (1 << 18)
#define A64_TRAMP_SAVE_X19  (1 << 19)
#define A64_TRAMP_SAVE_X20  (1 << 20)
#define A64_TRAMP_SAVE_X21  (1 << 21)
#define A64_TRAMP_SAVE_X22  (1 << 22)
#define A64_TRAMP_SAVE_X23  (1 << 23)
#define A64_TRAMP_SAVE_X24  (1 << 24)
#define A64_TRAMP_SAVE_X25  (1 << 25)
#define A64_TRAMP_SAVE_X26  (1 << 26)
#define A64_TRAMP_SAVE_X27  (1 << 27)
#define A64_TRAMP_SAVE_X28  (1 << 28)
#define A64_TRAMP_SAVE_X29  (1 << 29)
#define A64_TRAMP_SAVE_X30  (1 << 30)

#define A64_TRAMP_SAVE_ALL  0xffffffff
#define A64_TRAMP_SAVE_NONE 0x0
#define A64_TRAMP_SAVE_CALLER \
    (A64_TRAMP_SAVE_X0 | A64_TRAMP_SAVE_X1 | A64_TRAMP_SAVE_X2 | \
     A64_TRAMP_SAVE_X3 | A64_TRAMP_SAVE_X4 | A64_TRAMP_SAVE_X5 | \
     A64_TRAMP_SAVE_X6 | A64_TRAMP_SAVE_X7 | A64_TRAMP_SAVE_X8 | \
     A64_TRAMP_SAVE_X9 | A64_TRAMP_SAVE_X10 | A64_TRAMP_SAVE_X11 | \
     A64_TRAMP_SAVE_X12 | A64_TRAMP_SAVE_X13 | A64_TRAMP_SAVE_X14 | \
     A64_TRAMP_SAVE_X15 | A64_TRAMP_SAVE_X16 | A64_TRAMP_SAVE_X17)

/*
 * Inline helpers for instruction encoding/decoding
 */
static inline bool a64_insn_valid(u32 insn)
{
    return insn != 0 && insn != 0xffffffff;
}

static inline bool a64_insn_is_b(u32 insn)
{
    return (insn & 0xfc000000) == 0x14000000;
}

static inline bool a64_insn_is_bl(u32 insn)
{
    return (insn & 0xfc000000) == 0x94000000;
}

static inline bool a64_insn_is_bcond(u32 insn)
{
    return (insn & 0xfe000000) == 0x54000000;
}

static inline bool a64_insn_is_cbz(u32 insn)
{
    return (insn & 0x7e000000) == 0x34000000;
}

static inline bool a64_insn_is_tbz(u32 insn)
{
    return (insn & 0x7e000000) == 0x36000000;
}

static inline bool a64_insn_is_br(u32 insn)
{
    return (insn & 0xfffffc1f) == 0xd61f0000;
}

static inline bool a64_insn_is_nop(u32 insn)
{
    return insn == 0xd503201f;
}

static inline bool a64_insn_is_brk(u32 insn)
{
    return (insn & 0xfff80000) == 0xd4200000;
}

static inline u32 a64_insn_branch_offset(u32 insn)
{
    s32 off = (insn & 0x03ffffff) << 2;
    off = (off << 6) >> 6;
    return (u32)(off & 0xffffffff);
}

static inline bool a64_branch_in_range(unsigned long pc, unsigned long target)
{
    long offset = (long)(target - pc);
    return (offset >= -A64_HOOK_BRANCH_RANGE &&
            offset < A64_HOOK_BRANCH_RANGE);
}

static inline signed long a64_branch_target(unsigned long pc, u32 insn)
{
    u32 imm26 = insn & 0x03ffffff;
    s64 offset = (s64)imm26;
    if (offset & 0x02000000) offset |= ~(s64)0x03ffffff;
    offset <<= 2;
    return (signed long)(pc + offset);
}

/* Get destination register from instruction */
static inline u8 a64_insn_rd(u32 insn)
{
    return (insn >> 0) & 0x1f;
}

static inline u8 a64_insn_rn(u32 insn)
{
    return (insn >> 5) & 0x1f;
}

static inline u8 a64_insn_rm(u32 insn)
{
    return (insn >> 16) & 0x1f;
}

static inline u8 a64_insn_ra(u32 insn)
{
    return (insn >> 10) & 0x1f;
}

static inline u8 a64_insn_rt(u32 insn)
{
    return (insn >> 0) & 0x1f;
}

/*
 * Atomic instruction helpers for the hooking process
 */
static inline u32 a64_get_insn(volatile u32 *addr)
{
    u32 insn;
    insn = READ_ONCE(*addr);
    return insn;
}

static inline void a64_set_insn(volatile u32 *addr, u32 insn)
{
    WRITE_ONCE(*addr, insn);
}

/*
 * Cache management helpers
 */
static inline void a64_flush_dcache_range(unsigned long start, unsigned long end)
{
    unsigned long addr;
    for (addr = start & ~(cache_line_size() - 1);
         addr < end;
         addr += cache_line_size()) {
        asm volatile("dc cvac, %0" : : "r"(addr) : "memory");
    }
    dsb(ish);
}

static inline void a64_invalidate_icache_range(unsigned long start,
                                                unsigned long end)
{
    unsigned long addr;
    for (addr = start & ~(cache_line_size() - 1);
         addr < end;
         addr += cache_line_size()) {
        asm volatile("ic ivau, %0" : : "r"(addr) : "memory");
    }
    dsb(ish);
    isb();
}

static inline void a64_flush_bcache_range(unsigned long start, unsigned long end)
{
    unsigned long addr;
    for (addr = start & ~(cache_line_size() - 1);
         addr < end;
         addr += cache_line_size()) {
        asm volatile("dc civac, %0" : : "r"(addr) : "memory");
    }
    dsb(ish);
    isb();
}

/*
 ===========================================================================
  Data declarations (defined in the module)
 ===========================================================================
 */

extern struct list_head a64_hook_list;
extern spinlock_t a64_hook_list_lock;
extern struct a64_hook_global_stats a64_hook_stats;
extern struct a64_hook_percpu __percpu *a64_hook_percpu_stats;
extern struct kmem_cache *a64_hook_cache;
extern struct kmem_cache *a64_tramp_cache;
extern struct kmem_cache *a64_kprobe_cache;
extern struct kmem_cache *a64_dma_cache;
extern atomic_t a64_hook_count_atomic;
extern atomic_t a64_hook_enabled_count;
extern struct dentry *a64_hook_debugfs_dir;
extern unsigned int a64_hook_verbose;
extern unsigned int a64_hook_debug;
extern unsigned int a64_hook_max_hooks;
extern bool a64_hook_use_kprobes;
extern bool a64_hook_use_dma;
extern bool a64_hook_use_stop_machine;

/*
 * NEON/SIMD instruction table functions (a64_hook_neon.c)
 */
int a64_neon_lookup(u32 insn, char *mnemonic, size_t mnemonic_size);
int a64_neon_decode(u32 insn, struct a64_hook_insn *d);

/*
 * Crypto extension instruction table functions (a64_hook_crypto.c)
 */
int a64_crypto_lookup(u32 insn, char *mnemonic, size_t mnemonic_size);
int a64_crypto_decode(u32 insn, struct a64_hook_insn *d);

/*
 * SVE/SVE2 instruction table functions (a64_hook_sve.c)
 */
int a64_sve_lookup(u32 insn, char *mnemonic, size_t mnemonic_size);
int a64_sve_decode(u32 insn, struct a64_hook_insn *d);

/*
 * Hook integrity checker (a64_hook_integrity.c)
 */
int  a64_integrity_init(void);
void a64_integrity_exit(void);
int  a64_integrity_register(struct a64_hook *hook);
void a64_integrity_unregister(struct a64_hook *hook);
int  a64_integrity_verify_hook(struct a64_hook *hook, bool repair);
int  a64_integrity_run_checks(bool repair);

struct a64_integrity_stats;
int  a64_integrity_get_stats(struct a64_integrity_stats *stats);

/*
 * Hook performance monitoring (a64_hook_integrity.c)
 */
int  a64_perf_init(void);
void a64_perf_exit(void);
int  a64_perf_register(struct a64_hook *hook);
void a64_perf_unregister(struct a64_hook *hook);
void a64_perf_record(struct a64_hook *hook, u64 cycles);
int  a64_perf_get_stats(struct a64_hook *hook, u64 *calls,
                        u64 *avg_cycles, u64 *min_cycles, u64 *max_cycles);
void a64_perf_reset(void);

/*
 * Cycle counter helper
 */
static inline u64 a64_get_cycles(void)
{
    u64 val;
    asm volatile("isb; mrs %0, cntvct_el0" : "=r"(val));
    return val;
}

/*
 * Full system register database (a64_hook_sysreg_full.c)
 */
struct a64_sysreg_full;
int  a64_sysreg_full_lookup(u16 encoding, const char **name);
int  a64_sysreg_full_count(void);
const struct a64_sysreg_full *a64_sysreg_full_get(int idx);

/*
 * IOCTL interface for /dev/a64_hook
 * Available to both kernel and userspace.
 */
#define A64_IOC_MAGIC   0xA6

/* IOCTL request/response structs */
struct a64_ioc_hook {
    char  name[64];
    char  sym[128];
    int   result;
};

struct a64_ioc_unhook {
    char  name[64];
    int   result;
};

#define A64_IOC_MAX_HOOKS 64
struct a64_ioc_hook_entry {
    char         name[64];
    unsigned long target_addr;
    unsigned long handler_addr;
    int          type;
    int          state;
    unsigned long long hits;
    char         sym[128];
};

struct a64_ioc_list {
    int    count;
    struct a64_ioc_hook_entry hooks[A64_IOC_MAX_HOOKS];
};

struct a64_ioc_stats {
    unsigned long long uptime_jiffies;
    unsigned long long total_hooks;
    unsigned long long enabled_hooks;
    unsigned long long disabled_hooks;
    unsigned long long error_hooks;
    unsigned long long total_hits;
    unsigned long long dma_writes;
    unsigned long long bytes_written;
    unsigned long long cache_flushes;
    unsigned long long trampolines;
    unsigned long long kprobe_fallbacks;
    unsigned long long peak_hooks;
};

struct a64_ioc_hits {
    char  name[64];
    unsigned long long hits;
    int   result;
};

/* _IOC macros for userspace without kernel headers */
#ifndef _IOC
#define _IOC(dir, type, nr, size) \
    (((dir) << 30) | ((type) << 8) | ((nr) << 0) | ((unsigned int)(size) << 16))
#define _IOC_NONE  0U
#define _IOC_WRITE 1U
#define _IOC_READ  2U
#define _IO(type, nr)        _IOC(_IOC_NONE, (type), (nr), 0)
#define _IOR(type, nr, size) _IOC(_IOC_READ, (type), (nr), sizeof(size))
#define _IOW(type, nr, size) _IOC(_IOC_WRITE, (type), (nr), sizeof(size))
#define _IOWR(type, nr, size) _IOC(_IOC_READ|_IOC_WRITE, (type), (nr), sizeof(size))
#endif

#define A64_IOC_HOOK     _IOWR(A64_IOC_MAGIC, 1, struct a64_ioc_hook)
#define A64_IOC_KPROBE   _IOWR(A64_IOC_MAGIC, 2, struct a64_ioc_hook)
#define A64_IOC_UNHOOK   _IOWR(A64_IOC_MAGIC, 3, struct a64_ioc_unhook)
#define A64_IOC_LIST      _IOWR(A64_IOC_MAGIC, 4, struct a64_ioc_list)
#define A64_IOC_STATS     _IOR(A64_IOC_MAGIC, 5, struct a64_ioc_stats)
#define A64_IOC_HITS     _IOWR(A64_IOC_MAGIC, 6, struct a64_ioc_hits)
#define A64_IOC_CLEAR     _IO(A64_IOC_MAGIC, 7)
#define A64_IOC_SELFTEST  _IO(A64_IOC_MAGIC, 8)

/*
 * GUI IOCTL interface — kernel framebuffer overlay
 */
struct a64_ioc_gui_clear {
    u32                      color;
} __attribute__((packed));

struct a64_ioc_gui_text {
    int                      x;
    int                      y;
    u32                      fg_color;
    u32                      bg_color;
    char                     text[256];
} __attribute__((packed));

struct a64_ioc_gui_rect {
    int                      x;
    int                      y;
    int                      w;
    int                      h;
    u32                      color;
} __attribute__((packed));

struct a64_ioc_gui_pixel {
    int                      x;
    int                      y;
    u32                      color;
} __attribute__((packed));

struct a64_ioc_gui_fb {
    int                      width;
    int                      height;
    int                      bpp;
    size_t                   size;
    void __user              *buffer;
} __attribute__((packed));

#define A64_IOC_GUI_CLEAR   _IOW(A64_IOC_MAGIC, 20, struct a64_ioc_gui_clear)
#define A64_IOC_GUI_TEXT    _IOW(A64_IOC_MAGIC, 21, struct a64_ioc_gui_text)
#define A64_IOC_GUI_RECT    _IOW(A64_IOC_MAGIC, 22, struct a64_ioc_gui_rect)
#define A64_IOC_GUI_PIXEL   _IOW(A64_IOC_MAGIC, 23, struct a64_ioc_gui_pixel)
#define A64_IOC_GUI_GETFB   _IOR(A64_IOC_MAGIC, 24, struct a64_ioc_gui_fb)

/*
 * GUI framebuffer functions (a64_hook_gui.c)
 */
int a64_gui_init(void);
void a64_gui_exit(void);
void *a64_gui_get_fb(void);
int a64_gui_get_width(void);
int a64_gui_get_height(void);
int a64_gui_ioctl(unsigned int cmd, unsigned long arg);
void a64_gui_clear(u32 color);
int a64_gui_set_pixel(int x, int y, u32 color);
int a64_gui_fill_rect(int x, int y, int w, int h, u32 color);
int a64_gui_draw_text(int x, int y, u32 fg, u32 bg, const char *text);
int a64_gui_draw_line(int x0, int y0, int x1, int y1, u32 color);
int a64_gui_draw_rect_outline(int x, int y, int w, int h, u32 color);
int a64_gui_fill_circle(int cx, int cy, int r, u32 color);

/*
 * GUI window + animation system (a64_hook_gui_win.c)
 */
int a64_win_init(void);
void a64_win_exit(void);
int a64_gui_get_fps(void);
int a64_win_create(int x, int y, int w, int h, const char *title, u32 bg, u32 title_fg);
int a64_win_destroy(int id);
int a64_win_move(int id, int nx, int ny);
int a64_win_resize(int id, int nw, int nh);
int a64_win_set_title(int id, const char *title);
int a64_obj_create(int x, int y, int w, int h, u32 color);
int a64_obj_set_velocity(int id, int vx, int vy);
int a64_obj_destroy(int id);
void a64_anim_tick(void);
void a64_gui_hook_notify(const char *hook_name, unsigned long caller_pc,
                          struct pt_regs *regs);

#endif /* _A64_HOOK_H */
