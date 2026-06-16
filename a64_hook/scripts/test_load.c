#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifndef __NR_finit_module
#define __NR_finit_module 273
#endif
#ifndef __NR_init_module
#define __NR_init_module 105
#endif
#ifndef MODULE_INIT_IGNORE_MODVERSIONS
#define MODULE_INIT_IGNORE_MODVERSIONS 1
#endif
#ifndef MODULE_INIT_IGNORE_VERMAGIC
#define MODULE_INIT_IGNORE_VERMAGIC 2
#endif

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "/data/local/tmp/a64_hook.ko";
    const char *params = argc > 2 ? argv[2] : "";
    int flags = 0;
    if (argc > 3) {
        if (argv[3][0] == 'i') flags |= MODULE_INIT_IGNORE_MODVERSIONS;
        if (argv[3][1] == 'v') flags |= MODULE_INIT_IGNORE_VERMAGIC;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    struct stat st;
    fstat(fd, &st);
    printf("file size: %lld\n", (long long)st.st_size);

    // lseek to verify fd is seekable
    off_t off = lseek(fd, 0, SEEK_SET);
    printf("lseek result: %lld\n", (long long)off);
    if (off < 0) { perror("lseek"); }

    // Try finit_module with flags
    long r = syscall(__NR_finit_module, fd, params, flags);
    printf("finit_module: %ld errno=%d (%s)\n", r, errno, strerror(errno));

    close(fd);
    return 0;
}
