#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include "a64_hook.h"
#include "a64_hook_sym.h"

static int (*vgpu_fb_update_func)(void *pixels, unsigned int w, unsigned int h);

/* ---- tunables ---- */
#define A64_WIN_MAX_WINDOWS  8
#define A64_WIN_MAX_OBJECTS  16
#define A64_WIN_ANIM_FPS     60
#define A64_WIN_TITLE_H      12
#define A64_WIN_BORDER       1
#define A64_WIN_MIN_W        40
#define A64_WIN_MIN_H        30

/* ---- window ---- */
struct a64_gui_win {
    int                id;
    int                x, y, w, h;
    int                z;
    u32                bg, title_fg;
    char               title[56];
    bool               active;
    bool               dirty;
};

/* ---- moving object ---- */
struct a64_gui_obj {
    int                id;
    int                x, y, w, h;
    int                vx, vy;
    u32                color;
    bool               active;
    int                shape; /* 0=rect, 1=circle, 2=diamond */
};

/* ---- module state ---- */
static struct a64_gui_win_state {
    struct a64_gui_win  windows[A64_WIN_MAX_WINDOWS];
    int                 n_windows;
    int                 next_win_id;
    struct a64_gui_obj  objects[A64_WIN_MAX_OBJECTS];
    int                 n_objects;
    int                 next_obj_id;
    int                 fps;
    u64                 frame_count;
    u64                 last_fps_jiffies;
    u64                 hook_call_count;
    u64                 last_hook_jiffies;
    char                last_hook_name[64];
    unsigned long       last_hook_pc;
    struct hrtimer      anim_timer;
    ktime_t             anim_period;
    bool                active;
    spinlock_t          lock;
} a64_win;

/* ---- forward declarations ---- */
static enum hrtimer_restart a64_win_timer_cb(struct hrtimer *timer);
static int a64_win_hook_handler(struct pt_regs *regs, void *priv);

/* ---- helper: draw a filled diamond ---- */
static void obj_draw_diamond(struct a64_gui_obj *o)
{
    int cx = o->x + o->w / 2, cy = o->y + o->h / 2;
    int rx = o->w / 2, ry = o->h / 2;
    int px, py;
    for (py = cy - ry; py <= cy + ry; py++) {
        for (px = cx - rx; px <= cx + rx; px++) {
            int dx = abs(px - cx), dy = abs(py - cy);
            if (dx * ry + dy * rx <= rx * ry)
                a64_gui_set_pixel(px, py, o->color);
        }
    }
}

/* ---- draw a single window ---- */
static void a64_win_draw_one(struct a64_gui_win *w)
{
    int bar_y = w->y + A64_WIN_TITLE_H;
    u32 border = 0xFFFFFFFF, title_bg = 0xFF2C3E50;

    /* background */
    a64_gui_fill_rect(w->x, bar_y, w->w, w->h - A64_WIN_TITLE_H, w->bg);

    /* title bar */
    a64_gui_fill_rect(w->x, w->y, w->w, A64_WIN_TITLE_H, title_bg);

    /* border */
    a64_gui_draw_rect_outline(w->x, w->y, w->w, w->h, border);

    /* title underline */
    a64_gui_draw_line(w->x, bar_y - 1, w->x + w->w - 1, bar_y - 1, border);

    /* title text (centered) */
    if (w->title[0]) {
        int tx = w->x + 4, ty = w->y + 2;
        a64_gui_draw_text(tx, ty, w->title_fg, title_bg, w->title);
    }

    w->dirty = false;
}

/* ---- redraw entire scene ---- */
static void a64_win_redraw_all(void)
{
    int i;
    unsigned long flags;

    spin_lock_irqsave(&a64_win.lock, flags);

    /* sort windows by z-order then draw */
    /* simple bubble sort in-place by z */
    int changed;
    do {
        changed = 0;
        for (i = 0; i + 1 < a64_win.n_windows; i++) {
            struct a64_gui_win *a = &a64_win.windows[i];
            struct a64_gui_win *b = &a64_win.windows[i + 1];
            if (!a->active || !b->active) continue;
            if (a->z > b->z) {
                struct a64_gui_win tmp = *a;
                *a = *b;
                *b = tmp;
                changed = 1;
            }
        }
    } while (changed);

    for (i = 0; i < a64_win.n_windows; i++) {
        if (a64_win.windows[i].active)
            a64_win_draw_one(&a64_win.windows[i]);
    }

    /* draw moving objects on top */
    for (i = 0; i < a64_win.n_objects; i++) {
        struct a64_gui_obj *o = &a64_win.objects[i];
        if (!o->active) continue;
        switch (o->shape) {
        case 1:
            a64_gui_fill_circle(o->x + o->w / 2, o->y + o->h / 2,
                                min(o->w, o->h) / 2, o->color);
            break;
        case 2:
            obj_draw_diamond(o);
            break;
        default:
            a64_gui_fill_rect(o->x, o->y, o->w, o->h, o->color);
        }
    }

    /* FPS overlay (top-right corner) */
    {
        char fps_text[24];
        int len = scnprintf(fps_text, sizeof(fps_text), "FPS: %d", a64_win.fps);
        int fps_x = 640 - (len * 8 + 4);
        a64_gui_draw_text(fps_x, 2, 0xFF00FF00, 0, fps_text);
    }

    /* hook info overlay */
    if (a64_win.hook_call_count > 0) {
        char hook_text[80];
        scnprintf(hook_text, sizeof(hook_text),
                  "hooks: %llu last: %s",
                  a64_win.hook_call_count, a64_win.last_hook_name);
        a64_gui_draw_text(2, 2, 0xFFFFAA00, 0, hook_text);
    }

    spin_unlock_irqrestore(&a64_win.lock, flags);
}

/* ---- update object positions ---- */
static void a64_win_update_objects(void)
{
    int i;
    for (i = 0; i < a64_win.n_objects; i++) {
        struct a64_gui_obj *o = &a64_win.objects[i];
        if (!o->active) continue;

        o->x += o->vx;
        o->y += o->vy;

        if (o->x + o->w >= 640) { o->x = 640 - o->w - 1; o->vx = -o->vx; }
        if (o->x < 0)            { o->x = 0;               o->vx = -o->vx; }
        if (o->y + o->h >= 480) { o->y = 480 - o->h - 1; o->vy = -o->vy; }
        if (o->y < 0)            { o->y = 0;               o->vy = -o->vy; }
    }
}

/* ---- FPS calculation ---- */
static void a64_win_update_fps(void)
{
    u64 now = get_jiffies_64();
    a64_win.frame_count++;
    if (now - a64_win.last_fps_jiffies >= HZ) {
        a64_win.fps = (int)a64_win.frame_count;
        a64_win.frame_count = 0;
        a64_win.last_fps_jiffies = now;
    }
}

/* ---- hrtimer callback for animation ---- */
static enum hrtimer_restart a64_win_timer_cb(struct hrtimer *timer)
{
    a64_win_update_fps();
    a64_win_update_objects();
    a64_gui_clear(0xFF1A1A2E);
    a64_win_redraw_all();
    if (vgpu_fb_update_func)
        vgpu_fb_update_func(a64_gui_get_fb(), 640, 480);
    hrtimer_forward_now(timer, a64_win.anim_period);
    return HRTIMER_RESTART;
}

/* ---- hook handler that notifies GUI ---- */
static int a64_win_hook_handler(struct pt_regs *regs, void *priv)
{
    a64_gui_hook_notify("sched_hook", regs ? regs->pc : 0, regs);
    return 0;
}

/* ====================================================================
 * public API
 * ==================================================================== */

int a64_gui_get_fps(void)
{
    return a64_win.fps;
}

int a64_win_create(int x, int y, int w, int h,
                   const char *title, u32 bg, u32 title_fg)
{
    unsigned long flags;
    int id;
    struct a64_gui_win *wptr = NULL;

    if (w < A64_WIN_MIN_W) w = A64_WIN_MIN_W;
    if (h < A64_WIN_MIN_H) h = A64_WIN_MIN_H;

    spin_lock_irqsave(&a64_win.lock, flags);
    if (a64_win.n_windows >= A64_WIN_MAX_WINDOWS) {
        spin_unlock_irqrestore(&a64_win.lock, flags);
        return -ENOSPC;
    }

    wptr = &a64_win.windows[a64_win.n_windows++];
    id = a64_win.next_win_id++;
    wptr->id = id;
    wptr->x = x; wptr->y = y; wptr->w = w; wptr->h = h;
    wptr->z = a64_win.n_windows;
    wptr->bg = bg;
    wptr->title_fg = title_fg;
    if (title) strscpy(wptr->title, title, sizeof(wptr->title));
    else wptr->title[0] = '\0';
    wptr->active = true;
    wptr->dirty = true;
    spin_unlock_irqrestore(&a64_win.lock, flags);
    return id;
}

int a64_win_destroy(int id)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&a64_win.lock, flags);
    for (i = 0; i < a64_win.n_windows; i++) {
        if (a64_win.windows[i].active && a64_win.windows[i].id == id) {
            a64_win.windows[i].active = false;
            spin_unlock_irqrestore(&a64_win.lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&a64_win.lock, flags);
    return -ENOENT;
}

int a64_win_move(int id, int nx, int ny)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&a64_win.lock, flags);
    for (i = 0; i < a64_win.n_windows; i++) {
        if (a64_win.windows[i].active && a64_win.windows[i].id == id) {
            a64_win.windows[i].x = nx;
            a64_win.windows[i].y = ny;
            a64_win.windows[i].dirty = true;
            spin_unlock_irqrestore(&a64_win.lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&a64_win.lock, flags);
    return -ENOENT;
}

int a64_win_resize(int id, int nw, int nh)
{
    unsigned long flags;
    int i;

    if (nw < A64_WIN_MIN_W) nw = A64_WIN_MIN_W;
    if (nh < A64_WIN_MIN_H) nh = A64_WIN_MIN_H;

    spin_lock_irqsave(&a64_win.lock, flags);
    for (i = 0; i < a64_win.n_windows; i++) {
        if (a64_win.windows[i].active && a64_win.windows[i].id == id) {
            a64_win.windows[i].w = nw;
            a64_win.windows[i].h = nh;
            a64_win.windows[i].dirty = true;
            spin_unlock_irqrestore(&a64_win.lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&a64_win.lock, flags);
    return -ENOENT;
}

int a64_win_set_title(int id, const char *title)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&a64_win.lock, flags);
    for (i = 0; i < a64_win.n_windows; i++) {
        if (a64_win.windows[i].active && a64_win.windows[i].id == id) {
            if (title) strscpy(a64_win.windows[i].title, title,
                               sizeof(a64_win.windows[i].title));
            spin_unlock_irqrestore(&a64_win.lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&a64_win.lock, flags);
    return -ENOENT;
}

int a64_obj_create(int x, int y, int w, int h, u32 color)
{
    unsigned long flags;
    int id;

    struct a64_gui_obj *o;

    spin_lock_irqsave(&a64_win.lock, flags);
    if (a64_win.n_objects >= A64_WIN_MAX_OBJECTS) {
        spin_unlock_irqrestore(&a64_win.lock, flags);
        return -ENOSPC;
    }

    id = a64_win.next_obj_id++;
    o = &a64_win.objects[a64_win.n_objects++];
    o->id = id;
    o->x = x; o->y = y; o->w = w; o->h = h;
    o->vx = 0; o->vy = 0;
    o->color = color;
    o->active = true;
    o->shape = 0;
    spin_unlock_irqrestore(&a64_win.lock, flags);
    return id;
}

int a64_obj_set_velocity(int id, int vx, int vy)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&a64_win.lock, flags);
    for (i = 0; i < a64_win.n_objects; i++) {
        if (a64_win.objects[i].active && a64_win.objects[i].id == id) {
            a64_win.objects[i].vx = vx;
            a64_win.objects[i].vy = vy;
            spin_unlock_irqrestore(&a64_win.lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&a64_win.lock, flags);
    return -ENOENT;
}

int a64_obj_destroy(int id)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&a64_win.lock, flags);
    for (i = 0; i < a64_win.n_objects; i++) {
        if (a64_win.objects[i].active && a64_win.objects[i].id == id) {
            a64_win.objects[i].active = false;
            spin_unlock_irqrestore(&a64_win.lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&a64_win.lock, flags);
    return -ENOENT;
}

void a64_gui_hook_notify(const char *hook_name, unsigned long caller_pc,
                          struct pt_regs *regs)
{
    unsigned long flags;
    spin_lock_irqsave(&a64_win.lock, flags);
    a64_win.hook_call_count++;
    a64_win.last_hook_jiffies = get_jiffies_64();
    if (hook_name)
        strscpy(a64_win.last_hook_name, hook_name,
                sizeof(a64_win.last_hook_name));
    a64_win.last_hook_pc = caller_pc;
    spin_unlock_irqrestore(&a64_win.lock, flags);
}

void a64_anim_tick(void)
{
    a64_win_update_fps();
    a64_win_update_objects();
    a64_gui_clear(0xFF1A1A2E);
    a64_win_redraw_all();
}

/* ====================================================================
 * proc interface
 * ==================================================================== */

static int a64_win_proc_show(struct seq_file *m, void *v)
{
    int i;
    unsigned long flags;

    seq_printf(m, "a64_hook GUI window system\n");
    seq_printf(m, "  FPS:          %d\n", a64_win.fps);
    seq_printf(m, "  Windows:      %d/%d\n", a64_win.n_windows, A64_WIN_MAX_WINDOWS);
    seq_printf(m, "  Objects:      %d/%d\n", a64_win.n_objects, A64_WIN_MAX_OBJECTS);
    seq_printf(m, "  Hook calls:   %llu\n", a64_win.hook_call_count);
    seq_printf(m, "  Last hook:    %s\n", a64_win.last_hook_name);
    seq_printf(m, "\n");

    spin_lock_irqsave(&a64_win.lock, flags);
    seq_printf(m, "Windows:\n");
    for (i = 0; i < a64_win.n_windows; i++) {
        struct a64_gui_win *w = &a64_win.windows[i];
        if (!w->active) continue;
        seq_printf(m, "  [%d] \"%s\" at (%d,%d) %dx%d z=%d\n",
                   w->id, w->title, w->x, w->y, w->w, w->h, w->z);
    }
    seq_printf(m, "Objects:\n");
    for (i = 0; i < a64_win.n_objects; i++) {
        struct a64_gui_obj *o = &a64_win.objects[i];
        if (!o->active) continue;
        seq_printf(m, "  [%d] shape=%d at (%d,%d) %dx%d vel=(%d,%d)\n",
                   o->id, o->shape, o->x, o->y, o->w, o->h, o->vx, o->vy);
    }
    spin_unlock_irqrestore(&a64_win.lock, flags);

    seq_printf(m, "\nWindow commands:\n");
    seq_printf(m, "  win_create <x> <y> <w> <h> <bg_color> <title_fg> <title>\n");
    seq_printf(m, "  win_destroy <id>\n");
    seq_printf(m, "  win_move <id> <x> <y>\n");
    seq_printf(m, "  win_resize <id> <w> <h>\n");
    seq_printf(m, "  win_title <id> <text>\n");
    seq_printf(m, "\nObject commands:\n");
    seq_printf(m, "  obj_create <x> <y> <w> <h> <color>\n");
    seq_printf(m, "  obj_vel <id> <vx> <vy>\n");
    seq_printf(m, "  obj_destroy <id>\n");
    seq_printf(m, "\nOther:\n");
    seq_printf(m, "  anim_on\n");
    seq_printf(m, "  anim_off\n");
    seq_printf(m, "  demo\n");
    seq_printf(m, "  hook_demo\n");
    return 0;
}

static int a64_win_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, a64_win_proc_show, inode->i_private);
}

static ssize_t a64_win_proc_write(struct file *file, const char __user *buf,
                                   size_t len, loff_t *off)
{
    char cmd[512], *p;
    int ret = 0;

    if (len >= sizeof(cmd)) return -EINVAL;
    if (copy_from_user(cmd, buf, len)) return -EFAULT;
    cmd[len] = '\0';
    if (len > 0 && cmd[len - 1] == '\n') cmd[len - 1] = '\0';

    p = cmd;
    while (*p == ' ') p++;

    /* ---- demo: create windows + objects + start anim ---- */
    if (strcmp(p, "demo") == 0) {
        int w1, w2, w3, o1, o2, o3;

        a64_gui_clear(0xFF1A1A2E);

        w1 = a64_win_create(20, 40, 280, 200,
                            "System Monitor", 0xAA111111, 0xFFFFFFFF);
        w2 = a64_win_create(320, 40, 300, 200,
                            "Hook Log", 0xAA1A1A2E, 0xFFFFFFFF);
        w3 = a64_win_create(100, 260, 440, 200,
                            "Canvas", 0xAA222222, 0xFFFFFFFF);

        /* draw diagonals in canvas window */
        a64_gui_draw_line(120, 280, 520, 440, 0xFFE94560);
        a64_gui_draw_line(520, 280, 120, 440, 0xFF0F3460);
        a64_gui_draw_line(320, 280, 320, 440, 0xFFFFFFFF);
        a64_gui_draw_line(120, 360, 520, 360, 0xFFFFFFFF);

        o1 = a64_obj_create(50, 50, 24, 24, 0xFFE94560);
        a64_obj_set_velocity(o1, 2, 1);
        o2 = a64_obj_create(40, 100, 28, 28, 0xFF0F3460);
        a64_obj_set_velocity(o2, -1, 2);
        o3 = a64_obj_create(200, 100, 18, 18, 0xFFF4D03F);
        a64_obj_set_velocity(o3, 2, -2);

        a64_win_set_title(w1, "System Monitor  (FPS: --)");
        a64_win_set_title(w2, "Hook Log  (idle)");
        a64_win_set_title(w3, "Canvas  (diagonals)");

        return len;
    }

    /* ---- anim_on / anim_off ---- */
    if (strcmp(p, "anim_on") == 0) {
        if (!a64_win.active) {
            a64_win.active = true;
            hrtimer_start(&a64_win.anim_timer, a64_win.anim_period,
                          HRTIMER_MODE_REL);
        }
        return len;
    }
    if (strcmp(p, "anim_off") == 0) {
        if (a64_win.active) {
            a64_win.active = false;
            hrtimer_cancel(&a64_win.anim_timer);
        }
        return len;
    }

        /* ---- hook_demo: install a hook to 'schedule' to demo hook->GUI wiring ---- */
    if (strcmp(p, "hook_demo") == 0) {
        int ret = a64_hook_install_by_name("gui_sched_hook", "schedule",
                                            a64_win_hook_handler, NULL,
                                            A64_HOOK_DEFAULT_FLAGS);
        if (ret < 0) {
            pr_info("a64_win: hook schedule failed (%d), trying __do_softirq\n", ret);
            ret = a64_hook_install_by_name("gui_sftirq_hook", "__do_softirq",
                                            a64_win_hook_handler, NULL,
                                            A64_HOOK_DEFAULT_FLAGS);
        }
        pr_info("a64_win: hook_demo install -> %d\n", ret);
        return len;
    }

    /* ---- win_create ---- */
    if (strncmp(p, "win_create ", 11) == 0) {
        int x, y, w, h;
        u32 bg, title_fg;
        char title[56] = "";
        p += 11;
        if (sscanf(p, "%d %d %d %d %x %x",
                   &x, &y, &w, &h, &bg, &title_fg) >= 6) {
            while (*p && *p < '0') p++;
            int skip = 0;
            while (*p) { if (*p == ' ') skip++; p++; if (skip >= 6) break; }
            while (*p == ' ') p++;
            if (*p) strscpy(title, p, sizeof(title));
            a64_win_create(x, y, w, h, *title ? title : NULL, bg, title_fg);
        }
        return len;
    }

    /* ---- win_destroy ---- */
    if (strncmp(p, "win_destroy ", 12) == 0) {
        int id;
        if (kstrtoint(p + 12, 0, &id) == 0) a64_win_destroy(id);
        return len;
    }

    /* ---- win_move ---- */
    if (strncmp(p, "win_move ", 9) == 0) {
        int id, nx, ny;
        if (sscanf(p + 9, "%d %d %d", &id, &nx, &ny) >= 3)
            a64_win_move(id, nx, ny);
        return len;
    }

    /* ---- win_resize ---- */
    if (strncmp(p, "win_resize ", 11) == 0) {
        int id, nw, nh;
        if (sscanf(p + 11, "%d %d %d", &id, &nw, &nh) >= 3)
            a64_win_resize(id, nw, nh);
        return len;
    }

    /* ---- win_title ---- */
    if (strncmp(p, "win_title ", 10) == 0) {
        int id;
        char title[56];
        if (sscanf(p + 10, "%d", &id) >= 1) {
            char *t = p + 10;
            while (*t && *t != ' ') t++;
            while (*t == ' ') t++;
            if (*t) a64_win_set_title(id, t);
        }
        return len;
    }

    /* ---- obj_create ---- */
    if (strncmp(p, "obj_create ", 11) == 0) {
        int x, y, w, h;
        u32 color;
        if (sscanf(p + 11, "%d %d %d %d %x", &x, &y, &w, &h, &color) >= 5)
            a64_obj_create(x, y, w, h, color);
        return len;
    }

    /* ---- obj_vel ---- */
    if (strncmp(p, "obj_vel ", 8) == 0) {
        int id, vx, vy;
        if (sscanf(p + 8, "%d %d %d", &id, &vx, &vy) >= 3)
            a64_obj_set_velocity(id, vx, vy);
        return len;
    }

    /* ---- obj_destroy ---- */
    if (strncmp(p, "obj_destroy ", 12) == 0) {
        int id;
        if (kstrtoint(p + 12, 0, &id) == 0) a64_obj_destroy(id);
        return len;
    }

    return len;
}

static int a64_win_proc_release(struct inode *inode, struct file *file)
{
    return single_release(inode, file);
}

static const struct proc_ops a64_win_proc_fops = {
    .proc_open    = a64_win_proc_open,
    .proc_read    = seq_read,
    .proc_write   = a64_win_proc_write,
    .proc_release = a64_win_proc_release,
    .proc_lseek   = seq_lseek,
};

/* ====================================================================
 * init / exit
 * ==================================================================== */

int a64_win_init(void)
{
    memset(&a64_win, 0, sizeof(a64_win));
    spin_lock_init(&a64_win.lock);
    a64_win.active = false;
    a64_win.anim_period = ktime_set(0, NSEC_PER_SEC / A64_WIN_ANIM_FPS);
    a64_win.last_fps_jiffies = get_jiffies_64();

    hrtimer_init(&a64_win.anim_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    a64_win.anim_timer.function = a64_win_timer_cb;

    if (!proc_create("a64_hook_win", 0666, NULL, &a64_win_proc_fops)) {
        pr_err("a64_win: failed to create proc entry\n");
        return -ENOMEM;
    }

    if (a64_sym.kallsyms_lookup_name)
        vgpu_fb_update_func = (void *)a64_sym.kallsyms_lookup_name("vgpu_fb_update");

    pr_info("a64_win: window system ready (anim %s)%s\n",
            a64_win.active ? "ON" : "OFF",
            vgpu_fb_update_func ? " + vfb" : "");
    return 0;
}

void a64_win_exit(void)
{
    if (a64_win.active) {
        a64_win.active = false;
        hrtimer_cancel(&a64_win.anim_timer);
    }

    remove_proc_entry("a64_hook_win", NULL);
    pr_info("a64_win: shutdown\n");
}
