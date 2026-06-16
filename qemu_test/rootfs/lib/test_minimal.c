#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

static int __init test_minimal_init(void)
{
    printk(KERN_EMERG "test_minimal: INIT CALLED\n");
    return 0;
}

static void __exit test_minimal_exit(void)
{
    printk(KERN_EMERG "test_minimal: EXIT\n");
}

module_init(test_minimal_init);
module_exit(test_minimal_exit);
MODULE_LICENSE("GPL");
