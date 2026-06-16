// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>

static int __init test_init(void)
{
    printk(KERN_EMERG "test_module: init function EXECUTED\n");
    return 0;
}

static void __exit test_exit(void)
{
    printk(KERN_EMERG "test_module: exit\n");
}

module_init(test_init);
module_exit(test_exit);
MODULE_LICENSE("GPL");
