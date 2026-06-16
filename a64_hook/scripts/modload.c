#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef MODULE_INIT_IGNORE_MODVERSIONS
#define MODULE_INIT_IGNORE_MODVERSIONS 1
#endif
#ifndef MODULE_INIT_IGNORE_VERMAGIC
#define MODULE_INIT_IGNORE_VERMAGIC 2
#endif

#define KSYM_SENTINEL 0xDEADBEEF00000001UL

static void lower_kptr_restrict(void)
{
    int fd = open("/proc/sys/kernel/kptr_restrict", O_WRONLY);
    if (fd >= 0) {
        write(fd, "1\n", 2);
        close(fd);
    }
}

static unsigned long find_sym(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        unsigned long addr;
        char type, sym[256];
        if (sscanf(line, "%lx %c %255s", &addr, &type, sym) >= 3 &&
            strcmp(sym, name) == 0) {
            fclose(f);
            return addr;
        }
    }
    fclose(f);
    return 0;
}

static int patch_sentinel(const char *src_path, const char *dst_path,
                          unsigned long new_addr)
{
    FILE *f = fopen(src_path, "rb");
    if (!f) { perror("fopen src"); return -1; }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    unsigned char *buf = malloc(size);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, size, f) != (size_t)size) {
        perror("fread"); free(buf); fclose(f); return -1;
    }
    fclose(f);

    unsigned char sentinel[8] = {
        0x01, 0x00, 0x00, 0x00,
        0xEF, 0xBE, 0xAD, 0xDE
    };

    int found = 0;
    for (long i = 0; i <= size - 8; i++) {
        if (memcmp(buf + i, sentinel, 8) == 0) {
            buf[i + 0] = (unsigned char)(new_addr >> 0);
            buf[i + 1] = (unsigned char)(new_addr >> 8);
            buf[i + 2] = (unsigned char)(new_addr >> 16);
            buf[i + 3] = (unsigned char)(new_addr >> 24);
            buf[i + 4] = (unsigned char)(new_addr >> 32);
            buf[i + 5] = (unsigned char)(new_addr >> 40);
            buf[i + 6] = (unsigned char)(new_addr >> 48);
            buf[i + 7] = (unsigned char)(new_addr >> 56);
            found = 1;
            fprintf(stderr, "Patched sentinel at offset 0x%lx\n", i);
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "ERROR: sentinel not found in %s\n", src_path);
        free(buf);
        return -1;
    }

    f = fopen(dst_path, "wb");
    if (!f) { perror("fopen dst"); free(buf); return -1; }

    if (fwrite(buf, 1, size, f) != (size_t)size) {
        perror("fwrite"); free(buf); fclose(f); return -1;
    }
    fclose(f);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    const char *modpath;
    char patched_path[4096];
    int fd, ret;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <module.ko>\n", argv[0]);
        fprintf(stderr, "  Patches kallsyms sentinel and loads the module.\n");
        fprintf(stderr, "  Then run 'rmmod <module>' to activate it.\n");
        return 1;
    }
    modpath = argv[1];

    lower_kptr_restrict();

    unsigned long ka = find_sym("kallsyms_lookup_name");
    if (!ka) {
        fprintf(stderr, "ERROR: kallsyms_lookup_name not found\n");
        return 1;
    }
    fprintf(stderr, "kallsyms_lookup_name = 0x%lx\n", ka);

    snprintf(patched_path, sizeof(patched_path),
             "%s.patched", modpath);
    ret = patch_sentinel(modpath, patched_path, ka);
    if (ret) return 1;

    fd = open(patched_path, O_RDONLY);
    if (fd < 0) { perror("open patched"); return 1; }

    ret = syscall(__NR_finit_module, fd, "",
                  MODULE_INIT_IGNORE_MODVERSIONS |
                  MODULE_INIT_IGNORE_VERMAGIC);
    close(fd);

    if (ret < 0) {
        perror("finit_module");
        return 1;
    }

    fprintf(stderr, "OK: module loaded from %s\n", patched_path);
    fprintf(stderr, "Run 'rmmod <modname>' to activate lifecycle\n");
    return 0;
}
