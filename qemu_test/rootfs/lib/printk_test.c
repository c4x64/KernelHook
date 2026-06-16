#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>

MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);

static int __init ptest_init(void)
{
    struct file *f;
    char msg[] = "<0>ptest: INIT VIA KMSG\n";
    loff_t pos = 0;

    printk(KERN_EMERG "ptest: printk from init\n");

    f = filp_open("/dev/kmsg", O_WRONLY, 0);
    if (!IS_ERR(f)) {
        kernel_write(f, msg, sizeof(msg)-1, &pos);
        filp_close(f, NULL);
    }

    f = filp_open("/dev/console", O_WRONLY, 0);
    if (!IS_ERR(f)) {
        char direct[] = "ptest: DIRECT CONSOLE WRITE\n";
        pos = 0;
        kernel_write(f, direct, sizeof(direct)-1, &pos);
        filp_close(f, NULL);
    }

    return 0;
}

static void __exit ptest_exit(void)
{
    printk(KERN_EMERG "ptest: EXIT\n");
}

module_init(ptest_init);
module_exit(ptest_exit);
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
