#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/delay.h>

static int __init my_init(void)
{
    pr_emerg("test_init: init_module called!\n");
    /* Also try via write to serial directly */
    void __iomem *uart = ioremap(0x9000000, 0x1000);
    if (uart) {
        /* PL011: UARTDR at offset 0x000 */
        const char *msg = "HELO\n";
        while (*msg) {
            iowrite32(*msg, uart + 0x000);
            msg++;
            udelay(100);
        }
        iounmap(uart);
    }
    return 0;
}

static void __exit my_exit(void)
{
    pr_emerg("test_init: cleanup_module called!\n");
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
