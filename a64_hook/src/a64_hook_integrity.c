/*
 * a64_hook_integrity.c - Hook Integrity & Runtime Monitoring
 *
 * Verifies installed hooks haven't been corrupted, monitors
 * execution latency, and provides runtime health check API.
 *
 * License: GPL v2
 */

#include "a64_hook.h"

struct a64_integrity_check {
    bool            modified;
    bool            patched_ok;
    u64             checked_at;
    u32             original_hash;
    u32             current_hash;
    struct a64_hook *hook;
};

static struct a64_integrity_check *integrity_entries;
static int integrity_n_entries;
static int integrity_capacity;
static DEFINE_MUTEX(integrity_lock);

static u32 a64_hash_orig_insns(const struct a64_hook_insn *insns, int n)
{
    u32 h = 0xdeadbeef;
    int i;
    for (i = 0; i < n; i++) {
        h ^= insns[i].insn;
        h = (h << 5) | (h >> 27);
        h ^= h >> 16;
    }
    return h;
}

int a64_integrity_init(void)
{
    integrity_capacity = 64;
    integrity_entries = kmalloc_array(integrity_capacity,
        sizeof(struct a64_integrity_check), GFP_KERNEL);
    if (!integrity_entries)
        return -ENOMEM;
    integrity_n_entries = 0;
    memset(integrity_entries, 0,
        integrity_capacity * sizeof(struct a64_integrity_check));
    return 0;
}

void a64_integrity_exit(void)
{
    mutex_lock(&integrity_lock);
    kfree(integrity_entries);
    integrity_entries = NULL;
    integrity_n_entries = 0;
    integrity_capacity = 0;
    mutex_unlock(&integrity_lock);
}

int a64_integrity_register(struct a64_hook *hook)
{
    struct a64_integrity_check *entry;
    int idx;

    if (!hook || !hook->target_addr || !hook->n_orig_insns)
        return -EINVAL;

    mutex_lock(&integrity_lock);

    if (integrity_n_entries >= integrity_capacity) {
        struct a64_integrity_check *new_entries;
        int new_cap = integrity_capacity * 2;
        new_entries = krealloc_array(integrity_entries, new_cap,
            sizeof(struct a64_integrity_check), GFP_KERNEL);
        if (!new_entries) {
            mutex_unlock(&integrity_lock);
            return -ENOMEM;
        }
        integrity_entries = new_entries;
        integrity_capacity = new_cap;
    }

    idx = integrity_n_entries++;
    entry = &integrity_entries[idx];

    entry->hook = hook;
    entry->original_hash = a64_hash_orig_insns(hook->orig_insns,
        hook->n_orig_insns);
    entry->current_hash = entry->original_hash;
    entry->modified = false;
    entry->patched_ok = true;
    entry->checked_at = a64_get_cycles();

    mutex_unlock(&integrity_lock);
    return 0;
}

void a64_integrity_unregister(struct a64_hook *hook)
{
    int i;

    mutex_lock(&integrity_lock);
    for (i = 0; i < integrity_n_entries; i++) {
        if (integrity_entries[i].hook == hook) {
            integrity_entries[i] = integrity_entries[--integrity_n_entries];
            break;
        }
    }
    mutex_unlock(&integrity_lock);
}

int a64_integrity_verify_hook(struct a64_hook *hook, bool repair)
{
    u32 current_hash;
    int ret = -1;
    int i;

    if (!hook || !hook->target_addr)
        return -EINVAL;

    mutex_lock(&integrity_lock);
    for (i = 0; i < integrity_n_entries; i++) {
        struct a64_integrity_check *chk = &integrity_entries[i];
        if (chk->hook != hook)
            continue;

        current_hash = a64_hash_orig_insns(hook->orig_insns, hook->n_orig_insns);

        if (current_hash != chk->original_hash) {
            if (repair && current_hash == chk->original_hash) {
                u32 branch = a64_insn_b(
                    (unsigned long)hook->target_addr,
                    (unsigned long)hook->handler_addr);
                if (branch) {
                    a64_patch_insn_smp(hook->target_addr, branch);
                    chk->modified = false;
                    chk->patched_ok = true;
                    ret = 1;
                } else {
                    ret = -EINVAL;
                }
            } else {
                ret = -1;
            }
        } else {
            ret = 0;
        }
        break;
    }
    mutex_unlock(&integrity_lock);

    return ret;
}

int a64_integrity_run_checks(bool repair)
{
    int i;
    int corrupted = 0;
    int repaired = 0;
    int errors = 0;

    mutex_lock(&integrity_lock);

    for (i = 0; i < integrity_n_entries; i++) {
        struct a64_integrity_check *entry = &integrity_entries[i];
        int ret;

        ret = a64_integrity_verify_hook(entry->hook, repair);
        if (ret == -1) {
            corrupted++;
        } else if (ret == 1) {
            repaired++;
        } else if (ret < 0) {
            errors++;
        }
        entry->checked_at = a64_get_cycles();
    }

    mutex_unlock(&integrity_lock);
    return corrupted ? -corrupted : repaired;
}

struct a64_integrity_stats {
    int total_hooks;
    int corrupted;
    int repaired;
    int errors;
    u64 last_check;
    size_t mem_used;
};

int a64_integrity_get_stats(struct a64_integrity_stats *stats)
{
    int i;

    if (!stats)
        return -EINVAL;

    memset(stats, 0, sizeof(*stats));

    mutex_lock(&integrity_lock);

    stats->total_hooks = integrity_n_entries;
    stats->mem_used = integrity_capacity * sizeof(struct a64_integrity_check);

    for (i = 0; i < integrity_n_entries; i++) {
        struct a64_integrity_check *entry = &integrity_entries[i];
        u32 current_hash;

        current_hash = a64_hash_orig_insns(entry->hook->orig_insns,
            entry->hook->n_orig_insns);
        if (current_hash != entry->original_hash)
            stats->corrupted++;

        if (entry->checked_at > stats->last_check)
            stats->last_check = entry->checked_at;
    }

    mutex_unlock(&integrity_lock);
    return 0;
}

struct a64_perf_entry {
    u64             calls;
    u64             total_cycles;
    u64             min_cycles;
    u64             max_cycles;
    struct a64_hook *hook;
};

static struct a64_perf_entry *perf_entries;
static int perf_n_entries;
static int perf_capacity;
static DEFINE_MUTEX(perf_lock);

int a64_perf_init(void)
{
    perf_capacity = 64;
    perf_entries = kmalloc_array(perf_capacity,
        sizeof(struct a64_perf_entry), GFP_KERNEL);
    if (!perf_entries)
        return -ENOMEM;
    perf_n_entries = 0;
    memset(perf_entries, 0,
        perf_capacity * sizeof(struct a64_perf_entry));
    return 0;
}

void a64_perf_exit(void)
{
    mutex_lock(&perf_lock);
    kfree(perf_entries);
    perf_entries = NULL;
    perf_n_entries = 0;
    perf_capacity = 0;
    mutex_unlock(&perf_lock);
}

int a64_perf_register(struct a64_hook *hook)
{
    struct a64_perf_entry *entry;

    if (!hook)
        return -EINVAL;

    mutex_lock(&perf_lock);

    if (perf_n_entries >= perf_capacity) {
        struct a64_perf_entry *new_entries;
        int new_cap = perf_capacity * 2;
        new_entries = krealloc_array(perf_entries, new_cap,
            sizeof(struct a64_perf_entry), GFP_KERNEL);
        if (!new_entries) {
            mutex_unlock(&perf_lock);
            return -ENOMEM;
        }
        perf_entries = new_entries;
        perf_capacity = new_cap;
    }

    entry = &perf_entries[perf_n_entries++];
    entry->hook = hook;
    entry->calls = 0;
    entry->total_cycles = 0;
    entry->min_cycles = ~0ULL;
    entry->max_cycles = 0;

    mutex_unlock(&perf_lock);
    return 0;
}

void a64_perf_unregister(struct a64_hook *hook)
{
    int i;

    mutex_lock(&perf_lock);
    for (i = 0; i < perf_n_entries; i++) {
        if (perf_entries[i].hook == hook) {
            perf_entries[i] = perf_entries[--perf_n_entries];
            break;
        }
    }
    mutex_unlock(&perf_lock);
}

void a64_perf_record(struct a64_hook *hook, u64 cycles)
{
    int i;

    for (i = 0; i < perf_n_entries; i++) {
        if (perf_entries[i].hook == hook) {
            perf_entries[i].calls++;
            perf_entries[i].total_cycles += cycles;
            if (cycles < perf_entries[i].min_cycles)
                perf_entries[i].min_cycles = cycles;
            if (cycles > perf_entries[i].max_cycles)
                perf_entries[i].max_cycles = cycles;
            break;
        }
    }
}

int a64_perf_get_stats(struct a64_hook *hook, u64 *calls,
                       u64 *avg_cycles, u64 *min_cycles, u64 *max_cycles)
{
    int i;

    mutex_lock(&perf_lock);

    for (i = 0; i < perf_n_entries; i++) {
        if (perf_entries[i].hook == hook) {
            if (calls)
                *calls = perf_entries[i].calls;
            if (avg_cycles) {
                if (perf_entries[i].calls > 0)
                    *avg_cycles = perf_entries[i].total_cycles /
                                  perf_entries[i].calls;
                else
                    *avg_cycles = 0;
            }
            if (min_cycles)
                *min_cycles = perf_entries[i].min_cycles == ~0ULL ?
                              0 : perf_entries[i].min_cycles;
            if (max_cycles)
                *max_cycles = perf_entries[i].max_cycles;
            mutex_unlock(&perf_lock);
            return 0;
        }
    }

    mutex_unlock(&perf_lock);
    return -ENOENT;
}

void a64_perf_reset(void)
{
    int i;
    mutex_lock(&perf_lock);
    for (i = 0; i < perf_n_entries; i++) {
        perf_entries[i].calls = 0;
        perf_entries[i].total_cycles = 0;
        perf_entries[i].min_cycles = ~0ULL;
        perf_entries[i].max_cycles = 0;
    }
    mutex_unlock(&perf_lock);
}
