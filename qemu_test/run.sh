#!/bin/bash
# QEMU launcher for a64_hook + GUI overlay
#
# Usage:
#   ./run.sh           - Automated test (nographic, no GUI)
#   ./run.sh gui       - GUI mode with VNC (connect to vnc://localhost:5900)
#
# GUI mode on macOS:
#   open vnc://localhost:5900

KERNEL=./Image
INITRD=./initramfs.cpio.gz
SHARE_DIR=$(pwd)/rootfs/share

mkdir -p "$SHARE_DIR"

BASE_ARGS=(
    -machine virt
    -cpu cortex-a57
    -m 512M
    -kernel "$KERNEL"
    -initrd "$INITRD"
    -append "console=ttyAMA0 root=/dev/ram rdinit=/init"
    -device virtio-gpu-pci
    -fsdev local,id=hostshare,path="$SHARE_DIR",security_model=mapped
    -device virtio-9p-pci,fsdev=hostshare,mount_tag=hostshare
)

if [ "$1" = "gui" ]; then
    echo "Starting QEMU with VNC display at vnc://localhost:5900"
    exec qemu-system-aarch64 \
        "${BASE_ARGS[@]}" \
        -display vnc=:0
else
    echo "Starting QEMU in automated test mode (no GUI)"
    exec qemu-system-aarch64 \
        "${BASE_ARGS[@]}" \
        -nographic
fi
