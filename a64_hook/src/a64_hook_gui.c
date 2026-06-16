#include <linux/kernel.h>
#include <linux/module.h>
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/ioctl.h>
#include "a64_hook.h"

#define A64_GUI_WIDTH   640
#define A64_GUI_HEIGHT  480
#define A64_GUI_BPP     4
#define A64_GUI_FBSIZE  (A64_GUI_WIDTH * A64_GUI_HEIGHT * A64_GUI_BPP)
#define A64_GUI_STRIDE  (A64_GUI_WIDTH * A64_GUI_BPP)

#define A64_GUI_FONT_W  8
#define A64_GUI_FONT_H  8
#define A64_GUI_CHARS_PER_LINE (A64_GUI_WIDTH / A64_GUI_FONT_W)
#define A64_GUI_LINES   (A64_GUI_HEIGHT / A64_GUI_FONT_H)

struct a64_gui_state {
    void            *fb;
    int             width;
    int             height;
    int             stride;
    int             bpp;
    struct proc_dir_entry *proc_entry;
    spinlock_t      lock;
    bool            active;
};

static struct a64_gui_state a64_gui;

static const unsigned char a64_font_8x8[95][8] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00 },
    { 0x66, 0x66, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x24, 0x24, 0x24, 0x7E, 0x24, 0x7E, 0x24, 0x24 },
    { 0x08, 0x3E, 0x44, 0x3E, 0x08, 0x44, 0x3E, 0x08 },
    { 0x62, 0x64, 0x08, 0x10, 0x20, 0x4C, 0x86, 0x00 },
    { 0x30, 0x48, 0x30, 0x50, 0x88, 0x88, 0x70, 0x00 },
    { 0x18, 0x18, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x08, 0x10, 0x20, 0x20, 0x20, 0x10, 0x08, 0x00 },
    { 0x20, 0x10, 0x08, 0x08, 0x08, 0x10, 0x20, 0x00 },
    { 0x00, 0x24, 0x18, 0x7E, 0x18, 0x24, 0x00, 0x00 },
    { 0x00, 0x08, 0x08, 0x3E, 0x08, 0x08, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x10 },
    { 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00 },
    { 0x04, 0x08, 0x08, 0x10, 0x10, 0x20, 0x40, 0x00 },
    { 0x3C, 0x42, 0x46, 0x4A, 0x52, 0x62, 0x3C, 0x00 },
    { 0x08, 0x18, 0x28, 0x08, 0x08, 0x08, 0x3E, 0x00 },
    { 0x3C, 0x42, 0x02, 0x0C, 0x30, 0x40, 0x7E, 0x00 },
    { 0x3C, 0x42, 0x02, 0x1C, 0x02, 0x42, 0x3C, 0x00 },
    { 0x0C, 0x14, 0x24, 0x44, 0x7E, 0x04, 0x04, 0x00 },
    { 0x7E, 0x40, 0x78, 0x04, 0x02, 0x44, 0x38, 0x00 },
    { 0x1C, 0x20, 0x40, 0x7C, 0x42, 0x42, 0x3C, 0x00 },
    { 0x7E, 0x02, 0x04, 0x08, 0x10, 0x20, 0x20, 0x00 },
    { 0x3C, 0x42, 0x42, 0x3C, 0x42, 0x42, 0x3C, 0x00 },
    { 0x3C, 0x42, 0x42, 0x3E, 0x02, 0x04, 0x38, 0x00 },
    { 0x00, 0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00 },
    { 0x00, 0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x10 },
    { 0x04, 0x08, 0x10, 0x20, 0x10, 0x08, 0x04, 0x00 },
    { 0x00, 0x00, 0x3C, 0x00, 0x00, 0x3C, 0x00, 0x00 },
    { 0x20, 0x10, 0x08, 0x04, 0x08, 0x10, 0x20, 0x00 },
    { 0x3C, 0x42, 0x02, 0x0C, 0x10, 0x00, 0x10, 0x00 },
    { 0x3C, 0x42, 0x4E, 0x52, 0x4E, 0x40, 0x3C, 0x00 },
    { 0x18, 0x24, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x00 },
    { 0x7C, 0x42, 0x42, 0x7C, 0x42, 0x42, 0x7C, 0x00 },
    { 0x3C, 0x42, 0x40, 0x40, 0x40, 0x42, 0x3C, 0x00 },
    { 0x78, 0x44, 0x42, 0x42, 0x42, 0x44, 0x78, 0x00 },
    { 0x7E, 0x40, 0x40, 0x7C, 0x40, 0x40, 0x7E, 0x00 },
    { 0x7E, 0x40, 0x40, 0x7C, 0x40, 0x40, 0x40, 0x00 },
    { 0x3C, 0x42, 0x40, 0x4E, 0x42, 0x42, 0x3C, 0x00 },
    { 0x42, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x42, 0x00 },
    { 0x3E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x3E, 0x00 },
    { 0x1E, 0x04, 0x04, 0x04, 0x04, 0x44, 0x38, 0x00 },
    { 0x42, 0x44, 0x48, 0x70, 0x48, 0x44, 0x42, 0x00 },
    { 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x7E, 0x00 },
    { 0x42, 0x66, 0x5A, 0x5A, 0x42, 0x42, 0x42, 0x00 },
    { 0x42, 0x62, 0x52, 0x4A, 0x46, 0x42, 0x42, 0x00 },
    { 0x3C, 0x42, 0x42, 0x42, 0x42, 0x42, 0x3C, 0x00 },
    { 0x7C, 0x42, 0x42, 0x7C, 0x40, 0x40, 0x40, 0x00 },
    { 0x3C, 0x42, 0x42, 0x42, 0x4A, 0x44, 0x3A, 0x00 },
    { 0x7C, 0x42, 0x42, 0x7C, 0x48, 0x44, 0x42, 0x00 },
    { 0x3C, 0x42, 0x40, 0x3C, 0x02, 0x42, 0x3C, 0x00 },
    { 0x7E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00 },
    { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x3C, 0x00 },
    { 0x42, 0x42, 0x42, 0x42, 0x42, 0x24, 0x18, 0x00 },
    { 0x42, 0x42, 0x42, 0x5A, 0x5A, 0x66, 0x42, 0x00 },
    { 0x42, 0x42, 0x24, 0x18, 0x24, 0x42, 0x42, 0x00 },
    { 0x42, 0x42, 0x24, 0x18, 0x18, 0x18, 0x18, 0x00 },
    { 0x7E, 0x02, 0x04, 0x08, 0x10, 0x20, 0x7E, 0x00 },
    { 0x1E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x1E, 0x00 },
    { 0x40, 0x20, 0x20, 0x10, 0x10, 0x08, 0x04, 0x00 },
    { 0x78, 0x18, 0x18, 0x18, 0x18, 0x18, 0x78, 0x00 },
    { 0x08, 0x14, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF },
    { 0x10, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x3C, 0x02, 0x3E, 0x42, 0x3E, 0x00 },
    { 0x40, 0x40, 0x7C, 0x42, 0x42, 0x42, 0x7C, 0x00 },
    { 0x00, 0x00, 0x3C, 0x42, 0x40, 0x42, 0x3C, 0x00 },
    { 0x02, 0x02, 0x3E, 0x42, 0x42, 0x42, 0x3E, 0x00 },
    { 0x00, 0x00, 0x3C, 0x42, 0x7E, 0x40, 0x3C, 0x00 },
    { 0x0C, 0x12, 0x10, 0x7C, 0x10, 0x10, 0x10, 0x00 },
    { 0x00, 0x00, 0x3E, 0x42, 0x42, 0x3E, 0x02, 0x3C },
    { 0x40, 0x40, 0x7C, 0x42, 0x42, 0x42, 0x42, 0x00 },
    { 0x08, 0x00, 0x18, 0x08, 0x08, 0x08, 0x3E, 0x00 },
    { 0x04, 0x00, 0x0C, 0x04, 0x04, 0x04, 0x44, 0x38 },
    { 0x40, 0x40, 0x44, 0x48, 0x70, 0x48, 0x44, 0x00 },
    { 0x18, 0x08, 0x08, 0x08, 0x08, 0x08, 0x3E, 0x00 },
    { 0x00, 0x00, 0x76, 0x49, 0x49, 0x49, 0x49, 0x00 },
    { 0x00, 0x00, 0x7C, 0x42, 0x42, 0x42, 0x42, 0x00 },
    { 0x00, 0x00, 0x3C, 0x42, 0x42, 0x42, 0x3C, 0x00 },
    { 0x00, 0x00, 0x7C, 0x42, 0x42, 0x7C, 0x40, 0x40 },
    { 0x00, 0x00, 0x3E, 0x42, 0x42, 0x3E, 0x02, 0x02 },
    { 0x00, 0x00, 0x7C, 0x42, 0x40, 0x40, 0x40, 0x00 },
    { 0x00, 0x00, 0x3E, 0x40, 0x3C, 0x02, 0x7C, 0x00 },
    { 0x10, 0x10, 0x7C, 0x10, 0x10, 0x12, 0x0C, 0x00 },
    { 0x00, 0x00, 0x42, 0x42, 0x42, 0x42, 0x3E, 0x00 },
    { 0x00, 0x00, 0x42, 0x42, 0x42, 0x24, 0x18, 0x00 },
    { 0x00, 0x00, 0x49, 0x49, 0x49, 0x49, 0x36, 0x00 },
    { 0x00, 0x00, 0x42, 0x24, 0x18, 0x24, 0x42, 0x00 },
    { 0x00, 0x00, 0x42, 0x42, 0x42, 0x3E, 0x02, 0x3C },
    { 0x00, 0x00, 0x7E, 0x04, 0x08, 0x10, 0x7E, 0x00 },
    { 0x0C, 0x10, 0x10, 0x60, 0x10, 0x10, 0x0C, 0x00 },
    { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00 },
    { 0x30, 0x08, 0x08, 0x06, 0x08, 0x08, 0x30, 0x00 },
    { 0x60, 0x92, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00 },
};

static inline void gui_pixel(struct a64_gui_state *g, int x, int y, u32 color)
{
    u32 *p;
    if (x < 0 || x >= g->width || y < 0 || y >= g->height)
        return;
    p = (u32 *)((u8 *)g->fb + y * g->stride + x * g->bpp);
    *p = color;
}

static inline u32 gui_get_pixel(struct a64_gui_state *g, int x, int y)
{
    if (x < 0 || x >= g->width || y < 0 || y >= g->height)
        return 0;
    return *(u32 *)((u8 *)g->fb + y * g->stride + x * g->bpp);
}

void a64_gui_clear(u32 color)
{
    struct a64_gui_state *g = &a64_gui;
    unsigned long flags;
    u32 *p;
    int i, n;

    spin_lock_irqsave(&g->lock, flags);
    n = g->width * g->height;
    p = (u32 *)g->fb;
    for (i = 0; i < n; i++)
        p[i] = color;
    spin_unlock_irqrestore(&g->lock, flags);
}

int a64_gui_set_pixel(int x, int y, u32 color)
{
    struct a64_gui_state *g = &a64_gui;
    unsigned long flags;

    spin_lock_irqsave(&g->lock, flags);
    gui_pixel(g, x, y, color);
    spin_unlock_irqrestore(&g->lock, flags);
    return 0;
}

int a64_gui_fill_rect(int x, int y, int w, int h, u32 color)
{
    struct a64_gui_state *g = &a64_gui;
    unsigned long flags;
    int i, j;

    spin_lock_irqsave(&g->lock, flags);
    for (j = y; j < y + h && j < g->height; j++) {
        for (i = x; i < x + w && i < g->width; i++) {
            gui_pixel(g, i, j, color);
        }
    }
    spin_unlock_irqrestore(&g->lock, flags);
    return 0;
}

int a64_gui_draw_char(int x, int y, char c, u32 fg, u32 bg)
{
    struct a64_gui_state *g = &a64_gui;
    unsigned long flags;
    int row, col;
    unsigned char ch;

    if (c < 0x20 || c > 0x7E)
        ch = 0;
    else
        ch = (unsigned char)(c - 0x20);

    spin_lock_irqsave(&g->lock, flags);
    for (row = 0; row < 8 && y + row < g->height; row++) {
        unsigned char bits = a64_font_8x8[ch][row];
        for (col = 0; col < 8 && x + col < g->width; col++) {
            u32 color = (bits & (0x80 >> col)) ? fg : bg;
            gui_pixel(g, x + col, y + row, color);
        }
    }
    spin_unlock_irqrestore(&g->lock, flags);
    return 0;
}

int a64_gui_draw_text(int x, int y, u32 fg, u32 bg, const char *text)
{
    int cx = x, cy = y;
    char c;

    if (!text)
        return -EINVAL;

    while ((c = *text++) != '\0') {
        if (c == '\n') {
            cx = x;
            cy += 8;
            continue;
        }
        a64_gui_draw_char(cx, cy, c, fg, bg);
        cx += 8;
        if (cx + 8 > a64_gui.width) {
            cx = x;
            cy += 8;
        }
    }
    return 0;
}

static int a64_gui_proc_show(struct seq_file *m, void *v)
{
    struct a64_gui_state *g = &a64_gui;
    int x, y, ch_row;
    unsigned long flags;

    seq_printf(m, "a64_hook GUI framebuffer\n");
    seq_printf(m, "  Resolution: %dx%d\n", g->width, g->height);
    seq_printf(m, "  BPP:       %d\n", g->bpp * 8);
    seq_printf(m, "  Stride:    %d\n", g->stride);
    seq_printf(m, "  FB size:   %zu bytes\n", (size_t)g->width * g->height * g->bpp);
    seq_printf(m, "  Font:      8x8 bitmap\n");
    seq_printf(m, "  Chars:     %d x %d\n", g->width / 8, g->height / 8);
    seq_printf(m, "  Active:    %s\n", g->active ? "yes" : "no");
    seq_printf(m, "\nCommands: clear <hexcolor>, text <x> <y> <fg> <bg> <str>,\n");
    seq_printf(m, "          rect <x> <y> <w> <h> <color>, pixel <x> <y> <color>\n");
    seq_printf(m, "          getfb <file>, status\n");
    seq_printf(m, "Colors: 32-bit AARRGGBB hex\n");
    seq_printf(m, "\n--- ASCII preview (scaled 8x) ---\n");

    spin_lock_irqsave(&g->lock, flags);
    for (y = 0; y < g->height; y += 8) {
        for (x = 0; x < g->width; x += 8) {
            u32 p = gui_get_pixel(g, x, y);
            u8 r = (p >> 16) & 0xFF;
            u8 g_ = (p >> 8) & 0xFF;
            u8 b = p & 0xFF;
            u32 avg = (r + g_ + b) / 3;
            char c = " .:-=+*#@"[avg * 9 / 256];
            seq_putc(m, c);
        }
        seq_putc(m, '\n');
    }
    spin_unlock_irqrestore(&g->lock, flags);

    return 0;
}

static int a64_gui_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, a64_gui_proc_show, inode->i_private);
}

static ssize_t a64_gui_proc_write(struct file *file, const char __user *buf,
                                   size_t len, loff_t *off)
{
    char cmd[512], *p, *arg;
    int ret = 0;

    if (len >= sizeof(cmd))
        return -EINVAL;
    if (copy_from_user(cmd, buf, len))
        return -EFAULT;
    cmd[len] = '\0';
    if (len > 0 && cmd[len - 1] == '\n')
        cmd[len - 1] = '\0';

    p = cmd;
    while (*p == ' ') p++;

    if (strcmp(p, "status") == 0) {
        return len;
    }

    if (strncmp(p, "clear ", 6) == 0) {
        u32 color;
        if (kstrtou32(p + 6, 16, &color) == 0)
            a64_gui_clear(color);
        return len;
    }

    if (strncmp(p, "pixel ", 6) == 0) {
        int x, y;
        u32 color;
        if (sscanf(p + 6, "%d %d %x", &x, &y, &color) >= 3)
            a64_gui_set_pixel(x, y, color);
        return len;
    }

    if (strncmp(p, "rect ", 5) == 0) {
        int x, y, w, h;
        u32 color;
        if (sscanf(p + 5, "%d %d %d %d %x", &x, &y, &w, &h, &color) >= 5)
            a64_gui_fill_rect(x, y, w, h, color);
        return len;
    }

    if (strncmp(p, "text ", 5) == 0) {
        int x, y;
        u32 fg, bg;
        char text[256];
        p += 5;
        while (*p == ' ') p++;
        if (sscanf(p, "%d %d %x %x", &x, &y, &fg, &bg) >= 4) {
            arg = p;
            /* Skip past the 4 arguments to reach the text */
            int skip = 0;
            while (*arg && skip < 4) {
                if (*arg == ' ') skip++;
                arg++;
            }
            while (*arg == ' ') arg++;
            if (*arg == '"') {
                char *dst = text;
                arg++;
                while (*arg && *arg != '"' && dst < text + sizeof(text) - 1)
                    *dst++ = *arg++;
                *dst = '\0';
            } else {
                strscpy(text, arg, sizeof(text));
            }
            a64_gui_draw_text(x, y, fg, bg, text);
        }
        return len;
    }

    if (strncmp(p, "getfb ", 6) == 0) {
        struct file *f;
        char *fname = p + 6;
        while (*fname == ' ') fname++;
        if (*fname) {
            f = filp_open(fname, O_WRONLY | O_CREAT, 0644);
            if (IS_ERR(f)) {
                pr_warn("a64_gui: getfb open '%s' failed\n", fname);
            } else {
                loff_t pos = 0;
                kernel_write(f, a64_gui.fb,
                             a64_gui.width * a64_gui.height * a64_gui.bpp, &pos);
                filp_close(f, NULL);
                pr_info("a64_gui: getfb wrote %dx%dx%d to %s\n",
                        a64_gui.width, a64_gui.height, a64_gui.bpp, fname);
            }
        }
        return len;
    }

    return len;
}

static int a64_gui_proc_release(struct inode *inode, struct file *file)
{
    return single_release(inode, file);
}

static const struct proc_ops a64_gui_proc_fops = {
    .proc_open    = a64_gui_proc_open,
    .proc_read    = seq_read,
    .proc_write   = a64_gui_proc_write,
    .proc_release = a64_gui_proc_release,
    .proc_lseek   = seq_lseek,
};

int a64_gui_draw_line(int x0, int y0, int x1, int y1, u32 color)
{
    struct a64_gui_state *g = &a64_gui;
    int dx, dy, sx, sy, err, e2;
    unsigned long flags;

    dx = abs(x1 - x0);
    dy = -abs(y1 - y0);
    sx = x0 < x1 ? 1 : -1;
    sy = y0 < y1 ? 1 : -1;
    err = dx + dy;

    spin_lock_irqsave(&g->lock, flags);
    for (;;) {
        gui_pixel(g, x0, y0, color);
        if (x0 == x1 && y0 == y1) break;
        e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 += sx; }
        if (e2 <= dx) { err += dx; y0 += sy; }
    }
    spin_unlock_irqrestore(&g->lock, flags);
    return 0;
}

int a64_gui_draw_rect_outline(int x, int y, int w, int h, u32 color)
{
    a64_gui_draw_line(x, y, x + w - 1, y, color);
    a64_gui_draw_line(x + w - 1, y, x + w - 1, y + h - 1, color);
    a64_gui_draw_line(x + w - 1, y + h - 1, x, y + h - 1, color);
    a64_gui_draw_line(x, y + h - 1, x, y, color);
    return 0;
}

int a64_gui_fill_circle(int cx, int cy, int r, u32 color)
{
    struct a64_gui_state *g = &a64_gui;
    int x, y;
    unsigned long flags;

    spin_lock_irqsave(&g->lock, flags);
    for (y = cy - r; y <= cy + r; y++) {
        for (x = cx - r; x <= cx + r; x++) {
            if ((x - cx) * (x - cx) + (y - cy) * (y - cy) <= r * r)
                gui_pixel(g, x, y, color);
        }
    }
    spin_unlock_irqrestore(&g->lock, flags);
    return 0;
}

int a64_gui_ioctl(unsigned int cmd, unsigned long arg)
{
    void __user *argp = (void __user *)arg;

    switch (cmd) {
    case A64_IOC_GUI_CLEAR: {
        struct a64_ioc_gui_clear req;
        if (copy_from_user(&req, argp, sizeof(req)))
            return -EFAULT;
        a64_gui_clear(req.color);
        return 0;
    }

    case A64_IOC_GUI_TEXT: {
        struct a64_ioc_gui_text req;
        if (copy_from_user(&req, argp, sizeof(req)))
            return -EFAULT;
        req.text[sizeof(req.text) - 1] = '\0';
        return a64_gui_draw_text(req.x, req.y, req.fg_color,
                                 req.bg_color, req.text);
    }

    case A64_IOC_GUI_RECT: {
        struct a64_ioc_gui_rect req;
        if (copy_from_user(&req, argp, sizeof(req)))
            return -EFAULT;
        return a64_gui_fill_rect(req.x, req.y, req.w, req.h, req.color);
    }

    case A64_IOC_GUI_PIXEL: {
        struct a64_ioc_gui_pixel req;
        if (copy_from_user(&req, argp, sizeof(req)))
            return -EFAULT;
        return a64_gui_set_pixel(req.x, req.y, req.color);
    }

    case A64_IOC_GUI_GETFB: {
        struct a64_ioc_gui_fb req;
        size_t size;

        if (copy_from_user(&req, argp, sizeof(req)))
            return -EFAULT;

        req.size = a64_gui.width * a64_gui.height * a64_gui.bpp;
        if (req.buffer) {
            if (copy_to_user(req.buffer, a64_gui.fb, req.size))
                return -EFAULT;
        }
        req.width = a64_gui.width;
        req.height = a64_gui.height;
        req.bpp = a64_gui.bpp;

        if (copy_to_user(argp, &req, sizeof(req)))
            return -EFAULT;
        return 0;
    }

    default:
        return -ENOTTY;
    }
}

void *a64_gui_get_fb(void)
{
    return a64_gui.fb;
}

int a64_gui_get_width(void) { return a64_gui.width; }
int a64_gui_get_height(void) { return a64_gui.height; }

int a64_gui_init(void)
{
    struct a64_gui_state *g = &a64_gui;

    memset(g, 0, sizeof(*g));
    g->width = A64_GUI_WIDTH;
    g->height = A64_GUI_HEIGHT;
    g->bpp = A64_GUI_BPP;
    g->stride = A64_GUI_STRIDE;
    spin_lock_init(&g->lock);

    g->fb = vzalloc(A64_GUI_FBSIZE);
    if (!g->fb) {
        pr_err("a64_gui: failed to allocate framebuffer (%zu bytes)\n",
               (size_t)A64_GUI_FBSIZE);
        return -ENOMEM;
    }

    a64_gui_clear(0xFF1A1A2E);

    g->proc_entry = proc_create("a64_hook_gui", 0666, NULL,
                                &a64_gui_proc_fops);
    if (!g->proc_entry) {
        pr_err("a64_gui: failed to create proc entry\n");
        vfree(g->fb);
        g->fb = NULL;
        return -ENOMEM;
    }

    g->active = true;
    pr_info("a64_gui: initialized %dx%d 32bpp framebuffer\n",
            g->width, g->height);
    return 0;
}

void a64_gui_exit(void)
{
    struct a64_gui_state *g = &a64_gui;

    g->active = false;

    if (g->proc_entry) {
        remove_proc_entry("a64_hook_gui", NULL);
        g->proc_entry = NULL;
    }

    if (g->fb) {
        vfree(g->fb);
        g->fb = NULL;
    }

    pr_info("a64_gui: shutdown\n");
}
