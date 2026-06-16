#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define DEV_PATH "/dev/a64_hook"

#define A64_IOC_MAGIC 0xA6

/* _IOR is provided by <sys/ioctl.h> on Linux */
#ifndef _IOR
#error "_IOR macro required - include <sys/ioctl.h> on Linux"
#endif

struct a64_ioc_gui_fb {
    int width, height, bpp;
    size_t size;
    void *buffer;
} __attribute__((packed));

#define A64_IOC_GUI_GETFB _IOR(A64_IOC_MAGIC, 24, struct a64_ioc_gui_fb)

static int write_ppm(const char *path, void *pixels, int w, int h)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror("fopen"); return -1; }

    fprintf(f, "P6\n%d %d\n255\n", w, h);

    uint8_t *src = (uint8_t *)pixels;
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            uint32_t p = *(uint32_t *)(src + (y * w + x) * 4);
            uint8_t r = (p >> 16) & 0xFF;
            uint8_t g = (p >> 8) & 0xFF;
            uint8_t b = p & 0xFF;
            fwrite(&r, 1, 1, f);
            fwrite(&g, 1, 1, f);
            fwrite(&b, 1, 1, f);
        }
    }
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    const char *outpath = argc > 1 ? argv[1] : "/tmp/gui_output.ppm";

    int fd = open(DEV_PATH, O_RDWR);
    if (fd < 0) {
        perror("open " DEV_PATH);
        fprintf(stderr, "Is a64_hook.ko loaded?\n");
        return 1;
    }

    struct a64_ioc_gui_fb info;
    memset(&info, 0, sizeof(info));
    info.buffer = NULL;

    if (ioctl(fd, A64_IOC_GUI_GETFB, &info) < 0) {
        perror("ioctl GETFB (size query)");
        close(fd);
        return 1;
    }

    printf("Framebuffer: %dx%d %dbpp, size=%zu\n",
           info.width, info.height, info.bpp, info.size);

    void *buf = malloc(info.size);
    if (!buf) {
        fprintf(stderr, "malloc(%zu) failed\n", info.size);
        close(fd);
        return 1;
    }

    info.buffer = buf;
    if (ioctl(fd, A64_IOC_GUI_GETFB, &info) < 0) {
        perror("ioctl GETFB (read)");
        free(buf);
        close(fd);
        return 1;
    }

    close(fd);

    if (write_ppm(outpath, buf, info.width, info.height) < 0) {
        free(buf);
        return 1;
    }

    printf("Wrote %dx%d PPM: %s\n", info.width, info.height, outpath);
    free(buf);
    return 0;
}
