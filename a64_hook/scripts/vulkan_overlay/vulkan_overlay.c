#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "../liba64hook.h"

#define MAX_HOOK_DISPLAY     32
#define COL_BG              0xFF1A1A2E
#define COL_PANEL           0xFF16213E
#define COL_BORDER          0xFF0F3460
#define COL_TEXT            0xFFE8E8E8
#define COL_HIGHLIGHT       0xFF53D8FB
#define COL_ACCENT          0xFFE94560
#define COL_HITS            0xFF4ADE80
#define COL_FRAME_BG        0xFF0A0A1A

#define GUI_W                640
#define GUI_H                480

struct overlay_state {
    bool hook_ready;
    bool gui_ready;
    a64_lib_hook_info hooks[MAX_HOOK_DISPLAY];
    int num_hooks;
    a64_lib_stats stats;
    uint64_t frame_count;
};

static struct overlay_state app;

static void draw_panel(int x, int y, int w, int h)
{
    a64_lib_gui_rect(x, y, w, h, COL_PANEL);
    a64_lib_gui_rect(x, y, w, 1, COL_BORDER);
    a64_lib_gui_rect(x, y + h - 1, w, 1, COL_BORDER);
    a64_lib_gui_rect(x, y, 1, h, COL_BORDER);
    a64_lib_gui_rect(x + w - 1, y, 1, h, COL_BORDER);
}

static int render_frame(void)
{
    char buf[128];

    a64_lib_gui_clear(COL_BG);

    draw_panel(8, 8, GUI_W - 16, 36);
    a64_lib_gui_text(16, 12, COL_HIGHLIGHT, COL_PANEL,
                     "a64_hook v2.1.0 — Kernel GUI Overlay");

    snprintf(buf, sizeof(buf), "Frame: %llu", (unsigned long long)app.frame_count);
    a64_lib_gui_text(GUI_W - 150, 12, COL_ACCENT, COL_PANEL, buf);

    draw_panel(8, 52, (GUI_W - 24) / 2, 130);
    int px = 16, py = 58, ls = 10;
    a64_lib_gui_text(px, py, COL_HIGHLIGHT, COL_PANEL, "Global Statistics");
    py += 14;
    snprintf(buf, sizeof(buf), "Uptime (jiffies):  %llu",
             (unsigned long long)app.stats.uptime_jiffies);
    a64_lib_gui_text(px + 4, py, COL_TEXT, COL_PANEL, buf); py += ls;
    snprintf(buf, sizeof(buf), "Total hooks:       %llu",
             (unsigned long long)app.stats.total_hooks);
    a64_lib_gui_text(px + 4, py, COL_TEXT, COL_PANEL, buf); py += ls;
    snprintf(buf, sizeof(buf), "Enabled:           %llu",
             (unsigned long long)app.stats.enabled_hooks);
    a64_lib_gui_text(px + 4, py, COL_TEXT, COL_PANEL, buf); py += ls;
    snprintf(buf, sizeof(buf), "Total hits:        %llu",
             (unsigned long long)app.stats.total_hits);
    a64_lib_gui_text(px + 4, py, COL_HITS, COL_PANEL, buf); py += ls;
    snprintf(buf, sizeof(buf), "DMA writes:        %llu",
             (unsigned long long)app.stats.dma_writes);
    a64_lib_gui_text(px + 4, py, COL_TEXT, COL_PANEL, buf); py += ls;
    snprintf(buf, sizeof(buf), "Bytes written:     %llu",
             (unsigned long long)app.stats.bytes_written);
    a64_lib_gui_text(px + 4, py, COL_TEXT, COL_PANEL, buf); py += ls;
    snprintf(buf, sizeof(buf), "Trampolines:       %llu",
             (unsigned long long)app.stats.trampolines);
    a64_lib_gui_text(px + 4, py, COL_TEXT, COL_PANEL, buf);

    px = (GUI_W - 24) / 2 + 16;
    py = 58;
    a64_lib_gui_text(px, py, COL_HIGHLIGHT, COL_PANEL, "More Stats");
    py += 14;
    snprintf(buf, sizeof(buf), "Cache flushes:     %llu",
             (unsigned long long)app.stats.cache_flushes);
    a64_lib_gui_text(px + 4, py, COL_TEXT, COL_PANEL, buf); py += ls;
    snprintf(buf, sizeof(buf), "Kprobe fallbacks:  %llu",
             (unsigned long long)app.stats.kprobe_fallbacks);
    a64_lib_gui_text(px + 4, py, COL_TEXT, COL_PANEL, buf); py += ls;
    snprintf(buf, sizeof(buf), "Peak hooks:        %llu",
             (unsigned long long)app.stats.peak_hooks);
    a64_lib_gui_text(px + 4, py, COL_TEXT, COL_PANEL, buf);

    int list_y = 190;
    draw_panel(8, list_y, GUI_W - 16, GUI_H - list_y - 8);
    a64_lib_gui_text(16, list_y + 4, COL_HIGHLIGHT, COL_PANEL,
                     "Installed Hooks");
    int row = list_y + 18;
    if (app.num_hooks == 0) {
        a64_lib_gui_text(16, row, COL_TEXT, COL_PANEL,
                         "(none — install hooks with a64_lib_hook)");
    } else {
        int max_show = app.num_hooks;
        if (max_show > MAX_HOOK_DISPLAY) max_show = MAX_HOOK_DISPLAY;
        for (int i = 0; i < max_show && row + 8 < GUI_H - 10; i++) {
            const char *types[] = {"DETOUR", "KPROBE", "DMA"};
            const char *states[] = {"DIS", "EN", "ERR", "RM"};
            a64_lib_hook_info *h = &app.hooks[i];
            const char *t = (h->type >= 0 && h->type < 3) ? types[h->type] : "?";
            const char *s = (h->state >= 0 && h->state < 4) ? states[h->state] : "?";
            snprintf(buf, sizeof(buf), "  %-2d. %-20s %5s %3s hits:%llu",
                     i, h->name[0] ? h->name : "(unnamed)",
                     t, s, (unsigned long long)h->hits);
            uint32_t row_color = (i & 1) ? COL_TEXT : 0xFFC0C0C0;
            a64_lib_gui_text(16, row, row_color, COL_PANEL, buf);
            row += 9;
        }
    }

    return 0;
}

static int query_stats(void)
{
    a64_lib_stats s;
    int ret;

    if (!app.hook_ready)
        return -1;

    ret = a64_lib_get_stats(&s);
    if (ret == A64_LIB_OK)
        app.stats = s;

    app.num_hooks = 0;
    ret = a64_lib_list(app.hooks, &app.num_hooks);
    if (ret != A64_LIB_OK && ret != A64_LIB_ERR_NOTFOUND)
        return -1;

    return 0;
}

int main(void)
{
    printf("a64_hook Kernel GUI Overlay\n");
    printf("===========================\n\n");

    memset(&app, 0, sizeof(app));

    int ret = a64_lib_init();
    if (ret == A64_LIB_OK) {
        app.hook_ready = true;
        printf("[hook] liba64hook initialized\n");
    } else {
        printf("[hook] liba64hook init failed: %s\n", a64_lib_strerror(ret));
    }

    ret = a64_lib_gui_init();
    if (ret == A64_LIB_OK) {
        app.gui_ready = true;
        printf("[gui] kernel GUI initialized\n");
    } else {
        printf("[gui] kernel GUI init failed: %s\n", a64_lib_strerror(ret));
    }

    if (!app.gui_ready) {
        fprintf(stderr, "FATAL: Kernel GUI not available\n");
        fprintf(stderr, "Make sure a64_hook.ko is loaded (with GUI support)\n");
        goto out;
    }

    printf("\nRendering overlay to kernel framebuffer (640x480).\n");
    printf("Read /proc/a64_hook_gui for status or dump PPM via IOCTL.\n");
    printf("Press Ctrl+C to exit.\n\n");

    if (app.hook_ready) {
        ret = a64_lib_hook("demo_detour", "do_sys_open");
        if (ret == A64_LIB_OK)
            printf("[hook] Installed demo_detour\n");
        else
            printf("[hook] demo_detour: %s\n", a64_lib_strerror(ret));
    }

    while (1) {
        app.frame_count++;
        query_stats();
        render_frame();
        usleep(100000);
    }

out:
    if (app.gui_ready) a64_lib_gui_exit();
    if (app.hook_ready) a64_lib_exit();
    return 0;
}
