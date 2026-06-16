#include "liba64hook.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>

#define PROC_PATH   "/proc/a64_hook"
#define DEV_PATH    "/dev/a64_hook"
#define BUF_SIZE    (16 * 1024)

/* IOCTL definitions matching kernel header */
#define A64_IOC_MAGIC   0xA6
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

struct a64_ioc_gui_clear { uint32_t color; } __attribute__((packed));
struct a64_ioc_gui_text {
    int x, y;
    uint32_t fg_color, bg_color;
    char text[256];
} __attribute__((packed));
struct a64_ioc_gui_rect {
    int x, y, w, h;
    uint32_t color;
} __attribute__((packed));
struct a64_ioc_gui_pixel {
    int x, y;
    uint32_t color;
} __attribute__((packed));
struct a64_ioc_gui_fb {
    int width, height, bpp;
    size_t size;
    void *buffer;
} __attribute__((packed));

#define A64_IOC_GUI_CLEAR   _IOW(A64_IOC_MAGIC, 20, struct a64_ioc_gui_clear)
#define A64_IOC_GUI_TEXT    _IOW(A64_IOC_MAGIC, 21, struct a64_ioc_gui_text)
#define A64_IOC_GUI_RECT    _IOW(A64_IOC_MAGIC, 22, struct a64_ioc_gui_rect)
#define A64_IOC_GUI_PIXEL   _IOW(A64_IOC_MAGIC, 23, struct a64_ioc_gui_pixel)
#define A64_IOC_GUI_GETFB   _IOR(A64_IOC_MAGIC, 24, struct a64_ioc_gui_fb)

static int g_fd = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *err_msgs[] = {
    [0]  = "Success",
    [1]  = "General error",
    [2]  = "Symbol not found",
    [3]  = "Hook already exists",
    [4]  = "Hook not found",
    [5]  = "Permission denied",
    [6]  = "Communication error",
    [7]  = "Device not available",
    [8]  = "Resource busy",
    [9]  = "GUI error",
};

static int translate_write(ssize_t ret)
{
    if (ret < 0) {
        if (errno == ENOENT) return A64_LIB_ERR_NOSYM;
        if (errno == EEXIST) return A64_LIB_ERR_EXISTS;
        if (errno == EACCES || errno == EPERM) return A64_LIB_ERR_PERM;
        if (errno == ENODEV) return A64_LIB_ERR_NODEV;
        if (errno == EBUSY)  return A64_LIB_ERR_BUSY;
        return A64_LIB_ERR_COMM;
    }
    return A64_LIB_OK;
}

static int proc_write(const char *buf)
{
    size_t len = strlen(buf);
    ssize_t ret = write(g_fd, buf, len);
    return translate_write(ret);
}

static int proc_read(char *out, size_t outsz)
{
    off_t off = lseek(g_fd, 0, SEEK_SET);
    if (off < 0) return A64_LIB_ERR_COMM;
    ssize_t n = read(g_fd, out, outsz - 1);
    if (n < 0) return A64_LIB_ERR_COMM;
    out[n] = '\0';
    return A64_LIB_OK;
}

static int lookup_type(const char *s)
{
    if (strcmp(s, "DETOUR") == 0) return A64_LIB_TYPE_DETOUR;
    if (strcmp(s, "KPROBE") == 0) return A64_LIB_TYPE_KPROBE;
    if (strcmp(s, "DMA")    == 0) return A64_LIB_TYPE_DMA;
    return A64_LIB_TYPE_DETOUR;
}

static int lookup_state(const char *s)
{
    if (strcmp(s, "ENABLED")  == 0) return A64_LIB_STATE_ENABLED;
    if (strcmp(s, "DISABLED") == 0) return A64_LIB_STATE_DISABLED;
    if (strcmp(s, "ERROR")    == 0) return A64_LIB_STATE_ERROR;
    if (strcmp(s, "REMOVING") == 0) return A64_LIB_STATE_REMOVING;
    return A64_LIB_STATE_DISABLED;
}

int a64_lib_init(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_fd >= 0) {
        pthread_mutex_unlock(&g_lock);
        return A64_LIB_OK;
    }
    g_fd = open(PROC_PATH, O_RDWR);
    if (g_fd < 0) {
        pthread_mutex_unlock(&g_lock);
        return A64_LIB_ERR_NODEV;
    }
    pthread_mutex_unlock(&g_lock);
    return A64_LIB_OK;
}

void a64_lib_exit(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
    pthread_mutex_unlock(&g_lock);
}

int a64_lib_hook(const char *name, const char *target_symbol)
{
    char buf[512];
    int len = snprintf(buf, sizeof(buf), "hook %s %s", target_symbol, name);
    if (len < 0) return A64_LIB_ERR_GENERAL;

    pthread_mutex_lock(&g_lock);
    int ret = proc_write(buf);
    pthread_mutex_unlock(&g_lock);
    return ret;
}

int a64_lib_kprobe(const char *name, const char *target_symbol)
{
    char buf[512];
    int len = snprintf(buf, sizeof(buf), "kprobe %s %s", target_symbol, name);
    if (len < 0) return A64_LIB_ERR_GENERAL;

    pthread_mutex_lock(&g_lock);
    int ret = proc_write(buf);
    pthread_mutex_unlock(&g_lock);
    return ret;
}

int a64_lib_unhook(const char *name)
{
    char buf[512];
    int len = snprintf(buf, sizeof(buf), "unhook %s", name);
    if (len < 0) return A64_LIB_ERR_GENERAL;

    pthread_mutex_lock(&g_lock);
    int ret = proc_write(buf);
    pthread_mutex_unlock(&g_lock);
    return ret;
}

int a64_lib_list(a64_lib_hook_info *info, int *count)
{
    if (!info || !count) return A64_LIB_ERR_GENERAL;

    char buf[BUF_SIZE];
    int capacity = *count;
    int n = 0;

    pthread_mutex_lock(&g_lock);
    int ret = proc_read(buf, sizeof(buf));
    pthread_mutex_unlock(&g_lock);
    if (ret != A64_LIB_OK) return ret;

    char *line = buf;
    int skip_header = 1;
    while (line && *line) {
        char *next = strchr(line, '\n');
        if (next) *next++ = '\0';

        if (skip_header) {
            if (strstr(line, "Name") && strstr(line, "Target")) {
                skip_header = 0;
            }
        } else {
            char name[64], typ[16], state[16], sym[128];
            unsigned long long target_addr, hits;
            int parsed = sscanf(line, "%63s %15s %15s %llx %llu %127s",
                                name, typ, state, &target_addr, &hits, sym);
            if (parsed >= 5 && n < capacity) {
                a64_lib_hook_info *h = &info[n++];
                memset(h, 0, sizeof(*h));
                strncpy(h->name, name, sizeof(h->name) - 1);
                h->target_addr = target_addr;
                h->type = lookup_type(typ);
                h->state = lookup_state(state);
                h->hits = hits;
                if (parsed >= 6)
                    strncpy(h->symbol, sym, sizeof(h->symbol) - 1);
            }
        }
        line = next;
    }

    *count = n;
    return A64_LIB_OK;
}

int a64_lib_get_stats(a64_lib_stats *stats)
{
    if (!stats) return A64_LIB_ERR_GENERAL;
    memset(stats, 0, sizeof(*stats));

    char buf[BUF_SIZE];

    pthread_mutex_lock(&g_lock);
    int ret = proc_read(buf, sizeof(buf));
    pthread_mutex_unlock(&g_lock);
    if (ret != A64_LIB_OK) return ret;

    char *line = buf;
    while (line && *line) {
        char *next = strchr(line, '\n');
        if (next) *next++ = '\0';

        unsigned long long val;
        if (sscanf(line, "Uptime (jiffies): %llu", &val) == 1)
            stats->uptime_jiffies = val;
        else if (sscanf(line, "Total hooks: %llu", &val) == 1)
            stats->total_hooks = val;
        else if (sscanf(line, "Enabled: %llu", &val) == 1)
            stats->enabled_hooks = val;
        else if (sscanf(line, "Disabled: %llu", &val) == 1)
            stats->disabled_hooks = val;
        else if (sscanf(line, "Error: %llu", &val) == 1)
            stats->error_hooks = val;
        else if (sscanf(line, "Total hits: %llu", &val) == 1)
            stats->total_hits = val;
        else if (sscanf(line, "DMA writes: %llu", &val) == 1)
            stats->dma_writes = val;
        else if (sscanf(line, "Bytes written: %llu", &val) == 1)
            stats->bytes_written = val;
        else if (sscanf(line, "Cache flushes: %llu", &val) == 1)
            stats->cache_flushes = val;
        else if (sscanf(line, "Trampolines: %llu", &val) == 1)
            stats->trampolines = val;
        else if (sscanf(line, "Kprobe fallbacks: %llu", &val) == 1)
            stats->kprobe_fallbacks = val;
        else if (sscanf(line, "Peak hooks: %llu", &val) == 1)
            stats->peak_hooks = val;

        line = next;
    }

    return A64_LIB_OK;
}

long long a64_lib_hits(const char *name)
{
    a64_lib_hook_info infos[A64_LIB_MAX_HOOKS];
    int count = A64_LIB_MAX_HOOKS;
    int ret = a64_lib_list(infos, &count);
    if (ret != A64_LIB_OK) return ret;

    for (int i = 0; i < count; i++) {
        if (strcmp(infos[i].name, name) == 0)
            return (long long)infos[i].hits;
    }
    return A64_LIB_ERR_NOTFOUND;
}

int a64_lib_selftest(void)
{
    pthread_mutex_lock(&g_lock);
    int ret = proc_write("selftest");
    pthread_mutex_unlock(&g_lock);
    return ret;
}

int a64_lib_clear(void)
{
    pthread_mutex_lock(&g_lock);
    int ret = proc_write("clear");
    pthread_mutex_unlock(&g_lock);
    return ret;
}

const char *a64_lib_strerror(int err)
{
    int idx = -err;
    if (idx < 0 || (size_t)idx >= sizeof(err_msgs) / sizeof(err_msgs[0]))
        return "Unknown error";
    return err_msgs[idx];
}

/* ------------------------------------------------------------------ */
/* GUI functions — uses /dev/a64_hook IOCTLs                          */
/* ------------------------------------------------------------------ */

static int gui_dev_fd = -1;
static pthread_mutex_t gui_lock = PTHREAD_MUTEX_INITIALIZER;

int a64_lib_gui_init(void)
{
    pthread_mutex_lock(&gui_lock);
    if (gui_dev_fd >= 0) {
        pthread_mutex_unlock(&gui_lock);
        return A64_LIB_OK;
    }
    gui_dev_fd = open(DEV_PATH, O_RDWR);
    if (gui_dev_fd < 0) {
        pthread_mutex_unlock(&gui_lock);
        return A64_LIB_ERR_NODEV;
    }
    pthread_mutex_unlock(&gui_lock);
    return A64_LIB_OK;
}

void a64_lib_gui_exit(void)
{
    pthread_mutex_lock(&gui_lock);
    if (gui_dev_fd >= 0) {
        close(gui_dev_fd);
        gui_dev_fd = -1;
    }
    pthread_mutex_unlock(&gui_lock);
}

int a64_lib_gui_clear(uint32_t color)
{
    struct a64_ioc_gui_clear req = { .color = color };
    int ret;

    pthread_mutex_lock(&gui_lock);
    if (gui_dev_fd < 0) { pthread_mutex_unlock(&gui_lock); return A64_LIB_ERR_NODEV; }
    ret = ioctl(gui_dev_fd, A64_IOC_GUI_CLEAR, &req);
    pthread_mutex_unlock(&gui_lock);
    return ret ? A64_LIB_ERR_GUI : A64_LIB_OK;
}

int a64_lib_gui_text(int x, int y, uint32_t fg, uint32_t bg, const char *text)
{
    struct a64_ioc_gui_text req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.x = x; req.y = y;
    req.fg_color = fg; req.bg_color = bg;
    strncpy(req.text, text, sizeof(req.text) - 1);

    pthread_mutex_lock(&gui_lock);
    if (gui_dev_fd < 0) { pthread_mutex_unlock(&gui_lock); return A64_LIB_ERR_NODEV; }
    ret = ioctl(gui_dev_fd, A64_IOC_GUI_TEXT, &req);
    pthread_mutex_unlock(&gui_lock);
    return ret ? A64_LIB_ERR_GUI : A64_LIB_OK;
}

int a64_lib_gui_rect(int x, int y, int w, int h, uint32_t color)
{
    struct a64_ioc_gui_rect req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.x = x; req.y = y; req.w = w; req.h = h; req.color = color;

    pthread_mutex_lock(&gui_lock);
    if (gui_dev_fd < 0) { pthread_mutex_unlock(&gui_lock); return A64_LIB_ERR_NODEV; }
    ret = ioctl(gui_dev_fd, A64_IOC_GUI_RECT, &req);
    pthread_mutex_unlock(&gui_lock);
    return ret ? A64_LIB_ERR_GUI : A64_LIB_OK;
}

int a64_lib_gui_pixel(int x, int y, uint32_t color)
{
    struct a64_ioc_gui_pixel req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.x = x; req.y = y; req.color = color;

    pthread_mutex_lock(&gui_lock);
    if (gui_dev_fd < 0) { pthread_mutex_unlock(&gui_lock); return A64_LIB_ERR_NODEV; }
    ret = ioctl(gui_dev_fd, A64_IOC_GUI_PIXEL, &req);
    pthread_mutex_unlock(&gui_lock);
    return ret ? A64_LIB_ERR_GUI : A64_LIB_OK;
}

int a64_lib_gui_getfb(a64_lib_gui_fb_info *info, void *buffer, size_t *size)
{
    struct a64_ioc_gui_fb req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.buffer = buffer;
    req.size = *size;

    pthread_mutex_lock(&gui_lock);
    if (gui_dev_fd < 0) { pthread_mutex_unlock(&gui_lock); return A64_LIB_ERR_NODEV; }
    ret = ioctl(gui_dev_fd, A64_IOC_GUI_GETFB, &req);
    pthread_mutex_unlock(&gui_lock);

    if (ret) return A64_LIB_ERR_GUI;

    info->width = req.width;
    info->height = req.height;
    info->bpp = req.bpp;
    info->size = req.size;
    *size = req.size;
    return A64_LIB_OK;
}
