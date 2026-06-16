#include "liba64hook.h"
#include <stdio.h>
#include <string.h>

static void print_hook_info(const a64_lib_hook_info *h)
{
    const char *types[] = {"DETOUR", "KPROBE", "DMA"};
    const char *states[] = {"DISABLED", "ENABLED", "ERROR", "REMOVING"};
    printf("  %-20s %-8s %-10s 0x%016llx hits=%-5llu %s\n",
           h->name,
           (h->type >= 0 && h->type < 3) ? types[h->type] : "?",
           (h->state >= 0 && h->state < 4) ? states[h->state] : "?",
           (unsigned long long)h->target_addr,
           (unsigned long long)h->hits,
           h->symbol);
}

static void print_stats(const a64_lib_stats *s)
{
    printf("Uptime (jiffies): %llu\n", (unsigned long long)s->uptime_jiffies);
    printf("Total hooks:      %llu\n", (unsigned long long)s->total_hooks);
    printf("Enabled:          %llu\n", (unsigned long long)s->enabled_hooks);
    printf("Disabled:         %llu\n", (unsigned long long)s->disabled_hooks);
    printf("Error:            %llu\n", (unsigned long long)s->error_hooks);
    printf("Total hits:       %llu\n", (unsigned long long)s->total_hits);
    printf("DMA writes:       %llu\n", (unsigned long long)s->dma_writes);
    printf("Bytes written:    %llu\n", (unsigned long long)s->bytes_written);
    printf("Cache flushes:    %llu\n", (unsigned long long)s->cache_flushes);
    printf("Trampolines:      %llu\n", (unsigned long long)s->trampolines);
    printf("Kprobe fallbacks: %llu\n", (unsigned long long)s->kprobe_fallbacks);
    printf("Peak hooks:       %llu\n", (unsigned long long)s->peak_hooks);
}

int main(int argc, char **argv)
{
    if (a64_lib_init() != 0) {
        fprintf(stderr, "Failed to init a64_hook\n");
        return 1;
    }

    if (argc < 2) {
        printf("Usage: %s <command> [args...]\n", argv[0]);
        printf("Commands:\n");
        printf("  hook <func>     - Install hook\n");
        printf("  kprobe <func>   - Install kprobe hook\n");
        printf("  unhook <name>   - Remove hook\n");
        printf("  list            - List hooks\n");
        printf("  stats           - Show stats\n");
        printf("  hits <name>     - Get hit count\n");
        printf("  selftest        - Run selftest\n");
        printf("  clear           - Clear stats\n");
        a64_lib_exit();
        return 0;
    }

    int ret = 0;

    if (strcmp(argv[1], "hook") == 0 && argc >= 3) {
        const char *name = (argc >= 4) ? argv[3] : argv[2];
        ret = a64_lib_hook(name, argv[2]);
        printf("hook %s: %s (%d)\n", argv[2], a64_lib_strerror(ret), ret);
    } else if (strcmp(argv[1], "kprobe") == 0 && argc >= 3) {
        const char *name = (argc >= 4) ? argv[3] : argv[2];
        ret = a64_lib_kprobe(name, argv[2]);
        printf("kprobe %s: %s (%d)\n", argv[2], a64_lib_strerror(ret), ret);
    } else if (strcmp(argv[1], "unhook") == 0 && argc >= 3) {
        ret = a64_lib_unhook(argv[2]);
        printf("unhook %s: %s (%d)\n", argv[2], a64_lib_strerror(ret), ret);
    } else if (strcmp(argv[1], "list") == 0) {
        a64_lib_hook_info infos[A64_LIB_MAX_HOOKS];
        int count = A64_LIB_MAX_HOOKS;
        ret = a64_lib_list(infos, &count);
        if (ret == 0) {
            printf("  %-20s %-8s %-10s %-18s %s   %s\n",
                   "Name", "Type", "State", "Target", "Hits", "Symbol");
            for (int i = 0; i < count; i++)
                print_hook_info(&infos[i]);
        } else {
            printf("list: %s (%d)\n", a64_lib_strerror(ret), ret);
        }
    } else if (strcmp(argv[1], "stats") == 0) {
        a64_lib_stats s;
        ret = a64_lib_get_stats(&s);
        if (ret == 0) {
            print_stats(&s);
        } else {
            printf("stats: %s (%d)\n", a64_lib_strerror(ret), ret);
        }
    } else if (strcmp(argv[1], "hits") == 0 && argc >= 3) {
        long long hits = a64_lib_hits(argv[2]);
        if (hits >= 0)
            printf("hits %s: %lld\n", argv[2], hits);
        else
            printf("hits %s: %s (%lld)\n", argv[2], a64_lib_strerror((int)hits), hits);
    } else if (strcmp(argv[1], "selftest") == 0) {
        ret = a64_lib_selftest();
        printf("selftest: %s (%d)\n", a64_lib_strerror(ret), ret);
    } else if (strcmp(argv[1], "clear") == 0) {
        ret = a64_lib_clear();
        printf("clear: %s (%d)\n", a64_lib_strerror(ret), ret);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        ret = 1;
    }

    a64_lib_exit();
    return ret != 0 ? 1 : 0;
}
