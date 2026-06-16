//usr/bin/env -S docker run --rm -v /Users/prabhas/LibRizz:/build -w /build/a64_hook a64_hook_builder /bin/bash "$@"
// This is a self-executing Docker builder script. Do NOT delete the x bit.

set -euo pipefail

export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
export KDIR=/kernel

make clean
make -j$(nproc) all

# Also build userspace modload
echo "Building userspace tools..."
aarch64-linux-gnu-gcc -shared -fPIC -o /build/a64_hook/scripts/libmodstat.so /build/a64_hook/scripts/libmodstat.c -I/build/a64_hook/include -static
echo "Skipping modload - needs separate build"
