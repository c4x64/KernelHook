// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_gpu.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/spinlock.h>

#define VFB_WIDTH  640
#define VFB_HEIGHT 480
#define VFB_FORMAT VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM

struct vfb_device {
    struct virtio_device *vdev;
    struct virtqueue *ctrlq;
    struct virtqueue *cursorq;
    u32 resource_id;
    void *buf;
    dma_addr_t buf_dma;
    size_t buf_size;
    spinlock_t lock;
    struct completion ack;
};

static struct vfb_device *g_vfb;

static void vfb_ctrlq_cb(struct virtqueue *vq)
{
    struct vfb_device *vfb = vq->vdev->priv;
    complete(&vfb->ack);
}

static void vfb_cursorq_cb(struct virtqueue *vq) { }

static int vfb_setup_vqs(struct vfb_device *vfb)
{
    struct virtqueue *vqs[2];
    static const char * const names[] = { "control", "cursor" };
    vq_callback_t *cbs[] = { vfb_ctrlq_cb, vfb_cursorq_cb };
    int ret;
    ret = virtio_find_vqs(vfb->vdev, 2, vqs, cbs, names, NULL);
    if (ret) {
        printk(KERN_ERR "vfb: find_vqs failed: %d\n", ret);
        return ret;
    }
    vfb->ctrlq = vqs[0];
    vfb->cursorq = vqs[1];
    return 0;
}

static int vfb_send_cmd(struct vfb_device *vfb, void *cmd, int cmd_size,
                        void *resp, int resp_size)
{
    struct scatterlist sg_out, sg_in;
    struct scatterlist *sgs[2];
    unsigned long flags;
    int ret;

    sg_init_one(&sg_out, cmd, cmd_size);
    sg_init_one(&sg_in, resp, resp_size);
    sgs[0] = &sg_out;
    sgs[1] = &sg_in;

    if (virtqueue_is_broken(vfb->ctrlq)) {
        printk(KERN_EMERG "vfb: ctrlq BROKEN\n");
        return -EIO;
    }
    spin_lock_irqsave(&vfb->lock, flags);
    reinit_completion(&vfb->ack);
    ret = virtqueue_add_sgs(vfb->ctrlq, sgs, 1, 1, resp, GFP_ATOMIC);
    if (ret) {
        printk(KERN_EMERG "vfb: add_sgs fail ret=%d\n", ret);
        spin_unlock_irqrestore(&vfb->lock, flags);
        return ret;
    }
    virtqueue_kick(vfb->ctrlq);
    spin_unlock_irqrestore(&vfb->lock, flags);

    if (!wait_for_completion_timeout(&vfb->ack, msecs_to_jiffies(5000))) {
        printk(KERN_EMERG "vfb: cmd timeout\n");
        return -ETIMEDOUT;
    }
    return 0;
}

static int vfb_get_display_info(struct vfb_device *vfb)
{
    struct {
        struct virtio_gpu_ctrl_hdr cmd;
        struct virtio_gpu_resp_display_info resp;
    } __packed *p;
    int ret;

    p = kzalloc(sizeof(*p), GFP_KERNEL);
    if (!p) return -ENOMEM;
    p->cmd.type = cpu_to_le32(VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
    ret = vfb_send_cmd(vfb, &p->cmd, sizeof(p->cmd),
                       &p->resp, sizeof(p->resp));
    if (ret == 0)
        printk(KERN_INFO "vfb: scanout 0: %dx%d enabled=%d\n",
               le32_to_cpu(p->resp.pmodes[0].r.width),
               le32_to_cpu(p->resp.pmodes[0].r.height),
               le32_to_cpu(p->resp.pmodes[0].enabled));
    kfree(p);
    return ret;
}

static int vfb_create_resource_2d(struct vfb_device *vfb)
{
    struct {
        struct virtio_gpu_resource_create_2d cmd;
        struct virtio_gpu_ctrl_hdr resp;
    } __packed *p;
    int ret;

    p = kzalloc(sizeof(*p), GFP_KERNEL);
    if (!p) return -ENOMEM;
    p->cmd.hdr.type = cpu_to_le32(VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
    p->cmd.resource_id = cpu_to_le32(vfb->resource_id);
    p->cmd.format = cpu_to_le32(VFB_FORMAT);
    p->cmd.width = cpu_to_le32(VFB_WIDTH);
    p->cmd.height = cpu_to_le32(VFB_HEIGHT);
    ret = vfb_send_cmd(vfb, &p->cmd, sizeof(p->cmd),
                       &p->resp, sizeof(p->resp));
    kfree(p);
    return ret;
}

static int vfb_attach_backing(struct vfb_device *vfb)
{
    struct {
        struct virtio_gpu_resource_attach_backing hdr;
        struct virtio_gpu_mem_entry entry;
    } __packed *p;
    struct virtio_gpu_ctrl_hdr resp;
    int ret;

    p = kzalloc(sizeof(*p), GFP_KERNEL);
    if (!p) return -ENOMEM;
    p->hdr.hdr.type = cpu_to_le32(VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    p->hdr.resource_id = cpu_to_le32(vfb->resource_id);
    p->hdr.nr_entries = cpu_to_le32(1);
    p->entry.addr = cpu_to_le64(vfb->buf_dma);
    p->entry.length = cpu_to_le32(vfb->buf_size);
    p->entry.padding = 0;
    ret = vfb_send_cmd(vfb, &p->hdr, sizeof(*p), &resp, sizeof(resp));
    kfree(p);
    return ret;
}

static int vfb_set_scanout(struct vfb_device *vfb)
{
    struct {
        struct virtio_gpu_set_scanout cmd;
        struct virtio_gpu_ctrl_hdr resp;
    } __packed *p;
    int ret;

    p = kzalloc(sizeof(*p), GFP_KERNEL);
    if (!p) return -ENOMEM;
    p->cmd.hdr.type = cpu_to_le32(VIRTIO_GPU_CMD_SET_SCANOUT);
    p->cmd.r.x = 0;
    p->cmd.r.y = 0;
    p->cmd.r.width = cpu_to_le32(VFB_WIDTH);
    p->cmd.r.height = cpu_to_le32(VFB_HEIGHT);
    p->cmd.scanout_id = 0;
    p->cmd.resource_id = cpu_to_le32(vfb->resource_id);
    ret = vfb_send_cmd(vfb, &p->cmd, sizeof(p->cmd),
                       &p->resp, sizeof(p->resp));
    kfree(p);
    return ret;
}

static int vfb_fill_checkerboard(struct vfb_device *vfb)
{
    u32 *p = vfb->buf;
    int x, y;
    for (y = 0; y < VFB_HEIGHT; y++) {
        for (x = 0; x < VFB_WIDTH; x++) {
            int cx = x / 32, cy = y / 32;
            p[y * VFB_WIDTH + x] = ((cx + cy) & 1) ? 0xFFFFFFFF : 0xFF0000FF;
        }
    }
    return 0;
}

int vgpu_fb_update(void *pixels, u32 width, u32 height)
{
    struct vfb_device *vfb = g_vfb;
    struct {
        struct virtio_gpu_transfer_to_host_2d cmd;
        struct virtio_gpu_ctrl_hdr resp;
    } __packed *p;
    struct {
        struct virtio_gpu_resource_flush cmd;
        struct virtio_gpu_ctrl_hdr resp;
    } __packed *p2;
    int ret;

    if (!vfb || !pixels)
        return -ENODEV;
    if (width != VFB_WIDTH || height != VFB_HEIGHT)
        return -EINVAL;

    memcpy(vfb->buf, pixels, vfb->buf_size);

    p = kzalloc(sizeof(*p), GFP_KERNEL);
    if (!p) return -ENOMEM;
    p->cmd.hdr.type = cpu_to_le32(VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
    p->cmd.r.x = 0;
    p->cmd.r.y = 0;
    p->cmd.r.width = cpu_to_le32(VFB_WIDTH);
    p->cmd.r.height = cpu_to_le32(VFB_HEIGHT);
    p->cmd.offset = 0;
    p->cmd.resource_id = cpu_to_le32(vfb->resource_id);
    ret = vfb_send_cmd(vfb, &p->cmd, sizeof(p->cmd),
                       &p->resp, sizeof(p->resp));
    kfree(p);
    if (ret) return ret;

    p2 = kzalloc(sizeof(*p2), GFP_KERNEL);
    if (!p2) return -ENOMEM;
    p2->cmd.hdr.type = cpu_to_le32(VIRTIO_GPU_CMD_RESOURCE_FLUSH);
    p2->cmd.r.x = 0;
    p2->cmd.r.y = 0;
    p2->cmd.r.width = cpu_to_le32(VFB_WIDTH);
    p2->cmd.r.height = cpu_to_le32(VFB_HEIGHT);
    p2->cmd.resource_id = cpu_to_le32(vfb->resource_id);
    ret = vfb_send_cmd(vfb, &p2->cmd, sizeof(p2->cmd),
                       &p2->resp, sizeof(p2->resp));
    kfree(p2);
    return ret;
}
EXPORT_SYMBOL_GPL(vgpu_fb_update);

static int vfb_probe(struct virtio_device *vdev)
{
    struct vfb_device *vfb;
    int ret;

    printk(KERN_EMERG "vfb: probed id=%d feat=0x%llx\n", vdev->id.device, vdev->features);
    {
        u8 st = vdev->config->get_status(vdev);
        printk(KERN_EMERG "vfb: probe status id=%d st=%d\n", vdev->id.device, st);
    }

    vfb = kzalloc(sizeof(*vfb), GFP_KERNEL);
    if (!vfb) return -ENOMEM;

    vfb->vdev = vdev;
    vfb->resource_id = 1;
    spin_lock_init(&vfb->lock);
    init_completion(&vfb->ack);
    vdev->priv = vfb;

    printk(KERN_EMERG "vfb: calling find_vqs id=%d\n", vdev->id.device);
    ret = vfb_setup_vqs(vfb);
    printk(KERN_EMERG "vfb: find_vqs returned id=%d ret=%d\n", vdev->id.device, ret);
    if (ret) {
        goto fail_free;
    }
    printk(KERN_EMERG "vfb: vqs OK id=%d ctrl=%px(idx=%u nf=%u br=%d) cursor=%px(idx=%u nf=%u br=%d)\n",
           vdev->id.device,
           vfb->ctrlq, vfb->ctrlq->index, vfb->ctrlq->num_free, virtqueue_is_broken(vfb->ctrlq),
           vfb->cursorq, vfb->cursorq->index, vfb->cursorq->num_free, virtqueue_is_broken(vfb->cursorq));
    virtio_device_ready(vdev);

    ret = dma_set_coherent_mask(&vdev->dev, DMA_BIT_MASK(64));
    if (ret) {
        ret = dma_set_coherent_mask(&vdev->dev, DMA_BIT_MASK(32));
        if (ret) {
            printk(KERN_EMERG "vfb: dma_set_mask failed id=%d\n", vdev->id.device);
            goto fail_del_vqs;
        }
    }

    vfb->buf_size = VFB_WIDTH * VFB_HEIGHT * 4;
    vfb->buf = dma_alloc_coherent(&vdev->dev, vfb->buf_size,
                                   &vfb->buf_dma, GFP_KERNEL);
    if (!vfb->buf) {
        printk(KERN_EMERG "vfb: dma alloc failed id=%d\n", vdev->id.device);
        ret = -ENOMEM;
        goto fail_del_vqs;
    }

    ret = vfb_get_display_info(vfb);
    if (ret)
        printk(KERN_WARNING "vfb: get_display_info failed id=%d ret=%d\n", vdev->id.device, ret);
    else
        printk(KERN_EMERG "vfb: get_display_info OK id=%d\n", vdev->id.device);

    ret = vfb_create_resource_2d(vfb);
    if (ret) {
        printk(KERN_EMERG "vfb: resource_create_2d failed id=%d ret=%d\n", vdev->id.device, ret);
        goto fail_free_buf;
    }
    printk(KERN_EMERG "vfb: resource_create_2d OK id=%d\n", vdev->id.device);

    ret = vfb_attach_backing(vfb);
    if (ret) {
        printk(KERN_EMERG "vfb: attach_backing failed id=%d ret=%d\n", vdev->id.device, ret);
        goto fail_unref;
    }
    printk(KERN_EMERG "vfb: attach_backing OK id=%d\n", vdev->id.device);

    ret = vfb_set_scanout(vfb);
    if (ret) {
        printk(KERN_EMERG "vfb: set_scanout failed id=%d ret=%d\n", vdev->id.device, ret);
        goto fail_detach;
    }
    printk(KERN_EMERG "vfb: set_scanout OK id=%d\n", vdev->id.device);

    {
        int x, y;
        u32 *p = vfb->buf;
        for (y = 0; y < VFB_HEIGHT; y++)
            for (x = 0; x < VFB_WIDTH; x++)
                p[y * VFB_WIDTH + x] = ((x ^ y) & 16) ? 0xFFFFFFFF : 0xFF000000;
    }
    vgpu_fb_update(vfb->buf, VFB_WIDTH, VFB_HEIGHT);

    g_vfb = vfb;
    printk(KERN_INFO "vfb: init ok %dx%d res=%u\n",
           VFB_WIDTH, VFB_HEIGHT, vfb->resource_id);
    printk(KERN_EMERG "vfb: g_vfb SET=%p\n", g_vfb);
    return 0;

fail_detach: {
        struct virtio_gpu_resource_detach_backing cmd = {
            .hdr.type = cpu_to_le32(VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING),
            .resource_id = cpu_to_le32(vfb->resource_id),
        };
        struct virtio_gpu_ctrl_hdr resp;
        vfb_send_cmd(vfb, &cmd, sizeof(cmd), &resp, sizeof(resp));
    }
fail_unref: {
        struct virtio_gpu_resource_unref cmd = {
            .hdr.type = cpu_to_le32(VIRTIO_GPU_CMD_RESOURCE_UNREF),
            .resource_id = cpu_to_le32(vfb->resource_id),
        };
        struct virtio_gpu_ctrl_hdr resp;
        vfb_send_cmd(vfb, &cmd, sizeof(cmd), &resp, sizeof(resp));
    }
fail_free_buf:
    dma_free_coherent(&vdev->dev, vfb->buf_size, vfb->buf, vfb->buf_dma);
fail_del_vqs:
    vdev->config->del_vqs(vdev);
fail_free:
    kfree(vfb);
    return ret;
}

static void vfb_remove(struct virtio_device *vdev)
{
    struct vfb_device *vfb = vdev->priv;
    g_vfb = NULL;
    if (vfb) {
        if (vfb->buf)
            dma_free_coherent(&vdev->dev, vfb->buf_size,
                              vfb->buf, vfb->buf_dma);
        vdev->config->del_vqs(vdev);
        kfree(vfb);
    }
}

static unsigned int vfb_features[] = {
    VIRTIO_F_VERSION_1,
};

static struct virtio_device_id vfb_id_table[] = {
    { VIRTIO_DEV_ANY_ID, VIRTIO_DEV_ANY_ID },
    { 0 },
};

static struct virtio_driver vfb_driver = {
    .driver.name = "a64_hook_virtio_fb",
    .driver.owner = THIS_MODULE,
    .id_table = vfb_id_table,
    .feature_table = vfb_features,
    .feature_table_size = ARRAY_SIZE(vfb_features),
    .probe = vfb_probe,
    .remove = vfb_remove,
};

int a64_vfb_init(void)
{
    int ret;
    pr_emerg("vfb: registering virtio driver\n");
    ret = register_virtio_driver(&vfb_driver);
    pr_emerg("vfb: register=%d g_vfb=%p\n", ret, g_vfb);
    if (g_vfb) {
        vfb_fill_checkerboard(g_vfb);
        vgpu_fb_update(g_vfb->buf, VFB_WIDTH, VFB_HEIGHT);
        pr_emerg("vfb: checkerboard pushed\n");
    }
    return 0;
}

void a64_vfb_exit(void)
{
    pr_emerg("vfb: unregistering\n");
    unregister_virtio_driver(&vfb_driver);
}

//MODULE_DEVICE_TABLE(virtio, vfb_id_table);
