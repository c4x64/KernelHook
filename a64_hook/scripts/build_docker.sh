#!/bin/bash
# Build a64_hook kernel module using Docker + Android kernel build environment
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="/tmp/a64_hook_build"
OUTPUT_DIR="$PROJECT_DIR"
KERNEL_BRANCH="${KERNEL_BRANCH:-android13-5.15}"
CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"
IMAGE_NAME="a64_hook_builder"
VOLUME_NAME="a64_hook_kernel_src"
ACTION="${1:-build}"

mkdir -p "$BUILD_DIR"

if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "=== Building Docker image ==="
    docker build -t "$IMAGE_NAME" -f- "$PROJECT_DIR" << 'DOCKERFILE'
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential git flex bison libssl-dev libelf-dev bc cpio kmod \
    xz-utils curl wget ca-certificates python3 python3-pip file \
    gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu device-tree-compiler \
    --no-install-recommends && apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /build
DOCKERFILE
fi

setup_kernel() {
    echo "=== Setting up kernel source ==="
    docker run --rm \
        -v "$VOLUME_NAME:/build/kernel" \
        "$IMAGE_NAME" \
        bash -c '
set -e
if [ -f /build/kernel/.config ]; then
    echo "Kernel already cloned."
    exit 0
fi
cd /build
echo "Cloning Android kernel..."
git clone --depth=1 --branch '"$KERNEL_BRANCH"' \
    https://github.com/aosp-mirror/kernel_common.git kernel 2>&1 || \
git clone --depth=1 --branch '"$KERNEL_BRANCH"' \
    https://android.googlesource.com/kernel/common.git kernel 2>&1
cd kernel
make ARCH=arm64 defconfig 2>&1
make ARCH=arm64 modules_prepare 2>&1
echo "Kernel ready."
' 2>&1 | tail -5
}

build_module() {
    echo "=== Building a64_hook module ==="
    CID=$(docker run -d \
        -v "$VOLUME_NAME:/build/kernel" \
        -v "$PROJECT_DIR:/build/a64_hook_src:ro" \
        "$IMAGE_NAME" \
        bash -c '
set -e
rm -rf /build/a64_hook
cp -a /build/a64_hook_src /build/a64_hook
make -C /build/kernel M=/build/a64_hook modules \
    ARCH=arm64 CROSS_COMPILE='"$CROSS_COMPILE"' -j$(nproc)
cp /build/a64_hook/a64_hook.ko /tmp/
' 2>&1)
    if docker wait "$CID" >/dev/null 2>&1; then
        docker cp "$CID:/tmp/a64_hook.ko" "$BUILD_DIR/a64_hook.ko" 2>&1
        if [ -f "$BUILD_DIR/a64_hook.ko" ]; then
            echo "=== BUILD SUCCESS ==="
            file "$BUILD_DIR/a64_hook.ko"
            ls -lh "$BUILD_DIR/a64_hook.ko"
            cp "$BUILD_DIR/a64_hook.ko" "$OUTPUT_DIR/"
        else
            echo "=== BUILD FAILED (no .ko produced) ==="
            docker logs "$CID" 2>&1 | tail -30
            docker rm -f "$CID" >/dev/null 2>&1
            exit 1
        fi
    else
        echo "=== BUILD FAILED ==="
        docker logs "$CID" 2>&1 | tail -30
        docker rm -f "$CID" >/dev/null 2>&1
        exit 1
    fi
    docker rm -f "$CID" >/dev/null 2>&1
}

case "$ACTION" in
    setup)
        setup_kernel
        ;;
    build)
        if ! docker volume inspect "$VOLUME_NAME" &>/dev/null 2>&1; then
            setup_kernel
        fi
        build_module
        ;;
    *)
        echo "Usage: $0 [setup|build]"
        exit 1
        ;;
esac
