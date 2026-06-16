/*
 * a64_hook_dma.c - DMA-Based Physical Memory Operations
 *
 * Implements physical memory writes using DMA mapping for kernel text
 * patching on ARM64. Provides ioremap-based writing with DMA coherence
 * management and fallback to page-table manipulation when DMA is
 * unavailable. Designed for Android 12-16 (API 31+) ARM64 kernels.
 *
 * License: GPL v2
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/device.h>
#include <linux/dma-direct.h>
#include <linux/io.h>
#include <linux/cache.h>
#include <linux/highmem.h>
#include <linux/stop_machine.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/barrier.h>
#include <asm/io.h>

#include "a64_hook.h"
#include "a64_hook_sym.h"

static DEFINE_SPINLOCK(a64_dma_lock);

int a64_dma_init(struct a64_dma_mapping *dma, struct device *dev,
                  size_t size)
{
    if (!dma || !dev)
        return -EINVAL;

    memset(dma, 0, sizeof(*dma));
    dma->dev = dev;
    dma->size = PAGE_ALIGN(size);

    dma->virt_addr = dma_alloc_coherent(dev, dma->size,
                                          &dma->dma_handle, GFP_KERNEL);
    if (!dma->virt_addr)
        return -ENOMEM;

    dma->phys_addr = virt_to_phys(dma->virt_addr);
    dma->coherent = true;
    dma->mapped = true;
    spin_lock_init(&dma->lock);

    a64_hook_stats.total_dma_mappings++;

    return 0;
}

void a64_dma_exit(struct a64_dma_mapping *dma)
{
    if (!dma)
        return;

    if (dma->coherent && dma->virt_addr) {
        dma_free_coherent(dma->dev, dma->size,
                          dma->virt_addr, dma->dma_handle);
    }

    memset(dma, 0, sizeof(*dma));
}

static void __iomem *a64_ioremap_phys(phys_addr_t paddr, size_t size)
{
    return ioremap(paddr, size);
}

static void a64_iounmap_phys(volatile void __iomem *addr)
{
    iounmap(addr);
}

static int a64_write_via_setrw(unsigned long vaddr, const void *data, size_t size)
{
    if (a64_sym.aarch64_insn_write && size == 4)
        return a64_sym.aarch64_insn_write((void *)vaddr, *(const u32 *)data);

    {
        unsigned long page_start = vaddr & PAGE_MASK;
        unsigned long page_end = (vaddr + size + PAGE_SIZE - 1) & PAGE_MASK;
        int numpages = (page_end - page_start) / PAGE_SIZE;

        if (a64_sym.set_memory_rw)
            a64_sym.set_memory_rw(page_start, numpages);

        memcpy((void *)vaddr, data, size);

        if (a64_sym.set_memory_ro)
            a64_sym.set_memory_ro(page_start, numpages);
    }

    return 0;
}

int a64_dma_write_phys(phys_addr_t paddr, const void *data, size_t size)
{
    unsigned long flags;
    int ret = 0;

    if (!data || size == 0)
        return -EINVAL;

    spin_lock_irqsave(&a64_dma_lock, flags);
    ret = a64_write_via_setrw((unsigned long)phys_to_virt(paddr), data, size);
    spin_unlock_irqrestore(&a64_dma_lock, flags);

    a64_hook_stats.total_dma_writes++;
    a64_hook_stats.total_bytes_written += size;

    return ret;
}

int a64_dma_write_virt(unsigned long vaddr, const void *data, size_t size)
{
    unsigned long flags;
    int ret = 0;

    spin_lock_irqsave(&a64_dma_lock, flags);
    ret = a64_write_via_setrw(vaddr, data, size);
    spin_unlock_irqrestore(&a64_dma_lock, flags);

    a64_hook_stats.total_dma_writes++;
    a64_hook_stats.total_bytes_written += size;

    return ret;
}

int a64_dma_patch_text(unsigned long addr, u32 insn)
{
    return a64_dma_write_virt(addr, &insn, sizeof(insn));
}

int a64_dma_patch_text_batch(unsigned long addr, const u32 *insns, int n)
{
    return a64_dma_write_virt(addr, insns, n * sizeof(u32));
}

int a64_dma_sync(struct a64_dma_mapping *dma)
{
    if (!dma || !dma->coherent)
        return -EINVAL;

    dma_sync_single_for_device(dma->dev, dma->dma_handle,
                                dma->size, DMA_TO_DEVICE);
    return 0;
}

void a64_dma_flush_icache(unsigned long addr, size_t size)
{
    unsigned long start = addr & ~(cache_line_size() - 1);
    unsigned long end = (addr + size + cache_line_size() - 1) &
                         ~(cache_line_size() - 1);

    a64_flush_dcache_range(start, end);
    flush_icache_range(addr, addr + size);

    a64_hook_stats.total_cache_flushes++;
}

int a64_dma_map_target(unsigned long vaddr, struct a64_dma_mapping *dma)
{
    phys_addr_t paddr;
    void __iomem *mapped;

    if (!dma)
        return -EINVAL;

    paddr = a64_virt_to_phys((void *)vaddr);
    if (!paddr)
        return -EINVAL;

    memset(dma, 0, sizeof(*dma));
    dma->phys_addr = paddr;
    dma->size = PAGE_SIZE;
    spin_lock_init(&dma->lock);

    dma->virt_addr = a64_ioremap_phys(paddr, dma->size);
    if (!dma->virt_addr)
        return -ENOMEM;

    dma->mapped = true;
    dma->dev = NULL;

    a64_hook_stats.total_dma_mappings++;

    return 0;
}

void a64_dma_unmap_target(struct a64_dma_mapping *dma)
{
    if (!dma || !dma->mapped)
        return;

    if (dma->virt_addr)
        a64_iounmap_phys(dma->virt_addr);

    memset(dma, 0, sizeof(*dma));
}

int a64_dma_transfer(struct a64_dma_transfer *xfer)
{
    unsigned long flags;
    void __iomem *mapped;
    int ret = 0;

    if (!xfer || !xfer->source || xfer->size == 0)
        return -EINVAL;

    spin_lock_irqsave(&a64_dma_lock, flags);

    mapped = a64_ioremap_phys(xfer->target_paddr, xfer->size);
    if (!mapped) {
        spin_unlock_irqrestore(&a64_dma_lock, flags);
        return -ENOMEM;
    }

    memcpy_toio(mapped, xfer->source, xfer->size);
    a64_iounmap_phys(mapped);

    if (xfer->use_completion)
        complete_all(&xfer->done);

    xfer->status = 0;

    a64_hook_stats.total_dma_writes++;
    a64_hook_stats.total_bytes_written += xfer->size;

    spin_unlock_irqrestore(&a64_dma_lock, flags);

    return ret;
}

phys_addr_t a64_virt_to_phys(volatile void *addr)
{
    if (!addr)
        return 0;

    if (is_vmalloc_addr(addr))
        return page_to_phys(vmalloc_to_page(addr)) +
               offset_in_page(addr);

    return virt_to_phys((void *)addr);
}

void *a64_phys_to_virt(phys_addr_t addr)
{
    return phys_to_virt(addr);
}

int a64_check_patch_range(unsigned long from, unsigned long to)
{
    if (from >= to)
        return -EINVAL;

    if (from < (unsigned long)PAGE_OFFSET)
        return -EPERM;

    return 0;
}

int a64_patch_insn(unsigned long addr, u32 insn)
{
    return a64_dma_patch_text(addr, insn);
}

int a64_patch_insn_smp(unsigned long addr, u32 insn)
{
    int ret;

    ret = a64_dma_patch_text(addr, insn);
    if (ret < 0)
        return ret;

    a64_dma_flush_icache(addr, 4);
    return 0;
}

int a64_patch_branch(unsigned long addr, unsigned long target)
{
    u32 insn = a64_insn_b(addr, target);
    return a64_patch_insn_smp(addr, insn);
}

int a64_patch_bl(unsigned long addr, unsigned long target)
{
    u32 insn = a64_insn_bl(addr, target);
    return a64_patch_insn_smp(addr, insn);
}

int a64_patch_nop(unsigned long addr)
{
    return a64_patch_insn_smp(addr, a64_insn_nop());
}

int a64_patch_brk(unsigned long addr, u16 imm)
{
    return a64_patch_insn_smp(addr, a64_insn_brk(imm));
}

int a64_patch_ldr_literal(unsigned long addr, unsigned long target)
{
    u8 rt = ((addr & 0x1f));
    u32 insn = 0x18000000 | rt;
    s64 offset = (s64)(target - addr);
    insn |= ((offset & 0x1ffffc) << 3) >> 5;
    return a64_patch_insn_smp(addr, insn);
}

int a64_patch_movn(unsigned long addr, u64 val, int shift)
{
    return a64_patch_insn_smp(addr, a64_insn_movn(0, val, shift));
}

int a64_atomic_patch(struct a64_patch_work *work)
{
    if (!work)
        return -EINVAL;

    work->result = a64_patch_insn_smp(work->addr, work->insn);
    if (work->result == 0)
        work->old_insn = a64_get_insn((volatile u32 *)work->addr);

    if (work->use_completion)
        complete_all(&work->done);

    return work->result;
}
