#ifndef LIBA64_HOOK_H
#define LIBA64_HOOK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define A64_LIB_MAX_NAME        64
#define A64_LIB_MAX_SYMBOL      128
#define A64_LIB_MAX_HOOKS       256

#define A64_LIB_TYPE_DETOUR     0
#define A64_LIB_TYPE_KPROBE     1
#define A64_LIB_TYPE_DMA        2

#define A64_LIB_STATE_DISABLED  0
#define A64_LIB_STATE_ENABLED   1
#define A64_LIB_STATE_ERROR     2
#define A64_LIB_STATE_REMOVING  3

#define A64_LIB_OK              0
#define A64_LIB_ERR_GENERAL     -1
#define A64_LIB_ERR_NOSYM       -2
#define A64_LIB_ERR_EXISTS      -3
#define A64_LIB_ERR_NOTFOUND    -4
#define A64_LIB_ERR_PERM        -5
#define A64_LIB_ERR_COMM        -6
#define A64_LIB_ERR_NODEV       -7
#define A64_LIB_ERR_BUSY        -8
#define A64_LIB_ERR_GUI         -9

/* GUI framebuffer info */
typedef struct {
    int width;
    int height;
    int bpp;
    size_t size;
} a64_lib_gui_fb_info;

typedef struct {
    char name[A64_LIB_MAX_NAME];
    uint64_t target_addr;
    uint64_t handler_addr;
    int type;
    int state;
    uint64_t hits;
    char symbol[A64_LIB_MAX_SYMBOL];
} a64_lib_hook_info;

typedef struct {
    uint64_t uptime_jiffies;
    uint64_t total_hooks;
    uint64_t enabled_hooks;
    uint64_t disabled_hooks;
    uint64_t error_hooks;
    uint64_t total_hits;
    uint64_t dma_writes;
    uint64_t bytes_written;
    uint64_t cache_flushes;
    uint64_t trampolines;
    uint64_t kprobe_fallbacks;
    uint64_t peak_hooks;
} a64_lib_stats;

int a64_lib_init(void);
int a64_lib_hook(const char *name, const char *target_symbol);
int a64_lib_kprobe(const char *name, const char *target_symbol);
int a64_lib_unhook(const char *name);
int a64_lib_list(a64_lib_hook_info *info, int *count);
int a64_lib_get_stats(a64_lib_stats *stats);
long long a64_lib_hits(const char *name);
    int a64_lib_selftest(void);
int a64_lib_clear(void);
void a64_lib_exit(void);
const char *a64_lib_strerror(int err);

/* GUI functions – uses /dev/a64_hook IOCTL directly */
int  a64_lib_gui_init(void);
int  a64_lib_gui_clear(uint32_t color);
int  a64_lib_gui_text(int x, int y, uint32_t fg, uint32_t bg, const char *text);
int  a64_lib_gui_rect(int x, int y, int w, int h, uint32_t color);
int  a64_lib_gui_pixel(int x, int y, uint32_t color);
int  a64_lib_gui_getfb(a64_lib_gui_fb_info *info, void *buffer, size_t *size);
void a64_lib_gui_exit(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBA64_HOOK_H */
