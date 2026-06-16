# SPDX-License-Identifier: GPL-2.0
#
# Makefile for a64_hook - ARM64 Inline Hook Kernel Module
#
# Build with:
#   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
#   or in Android kernel tree:
#   make M=$(pwd) modules ARCH=arm64

A64_HOOK_VERSION := 2.1.0

obj-m += a64_hook.o

a64_hook-objs := \
    src/a64_hook_mod.o \
    src/a64_hook_core.o \
    src/a64_hook_disasm.o \
    src/a64_hook_emit.o \
    src/a64_hook_dma.o \
    src/a64_hook_kprobe.o \
    src/a64_hook_tramp.o \
    src/a64_hook_sysreg.o \
    src/a64_hook_insndb.o \
    src/a64_hook_neon.o \
    src/a64_hook_crypto.o \
    src/a64_hook_sve.o \
    src/a64_hook_integrity.o \
    src/a64_hook_sysreg_full.o \
    src/a64_hook_sym.o \
    src/a64_hook_gui.o \
    src/a64_hook_gui_win.o \
    src/a64_hook_virtio_fb.o

EXTRA_CFLAGS += -I$(src)/include
EXTRA_CFLAGS += -DA64_HOOK_VERSION=\"$(A64_HOOK_VERSION)\"
EXTRA_CFLAGS += -fno-strict-aliasing
EXTRA_CFLAGS += -O2
EXTRA_CFLAGS += -Wno-error
EXTRA_CFLAGS += -Wno-error=frame-larger-than=
EXTRA_CFLAGS += -Wno-frame-larger-than
EXTRA_CFLAGS += -Wno-attribute-alias
EXTRA_CFLAGS += -Wno-unused-variable
EXTRA_CFLAGS += -Wno-unused-function
EXTRA_CFLAGS += -Wno-strict-prototypes
EXTRA_CFLAGS += -Wno-int-conversion
EXTRA_CFLAGS += -Wno-discarded-qualifiers
EXTRA_CFLAGS += -Wno-sequence-point

ifdef A64_HOOK_DEBUG
EXTRA_CFLAGS += -DDEBUG -Og -g
endif

# Override UTS_RELEASE for cross-kernel compatibility
ifdef UTS_OVERRIDE
EXTRA_CFLAGS += -DUTS_RELEASE=\"$(UTS_OVERRIDE)\"
endif

# Android kernel build
ifdef ANDROID_KERNEL
EXTRA_CFLAGS += -DCONFIG_ANDROID
endif

# iOS/iOS jailbreak kernel build
ifdef IOS_KERNEL
EXTRA_CFLAGS += -DCONFIG_IOS
endif

# Static user-space test program
A64_HOOK_SRCS := src/a64_hook_emit.c src/a64_hook_disasm.c
a64_hook_test: scripts/a64_hook_test.c $(A64_HOOK_SRCS)
	$(CC) -o $@ scripts/a64_hook_test.c $(A64_HOOK_SRCS) \
		-Wall -Wextra -O2 -g -I./include -Isrc

test: a64_hook_test
	./a64_hook_test

clean:
	rm -f *.o *.ko *.mod.c *.mod *.symvers *.order
	rm -f src/*.o src/.*.o.cmd
	rm -f a64_hook_test
	rm -rf .tmp_versions Module.symvers modules.order

help:
	@echo "a64_hook v$(A64_HOOK_VERSION) Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build kernel module (requires kernel build tree)"
	@echo "  modules          - Alias for 'all'"
	@echo "  clean            - Remove build artifacts"
	@echo "  test             - Build and run user-space test"
	@echo "  install          - Install module (KERNELDIR required)"
	@echo ""
	@echo "Variables:"
	@echo "  KERNELDIR        - Path to kernel build tree"
	@echo "  ARCH             - Target architecture (default: arm64)"
	@echo "  CROSS_COMPILE    - Cross-compiler prefix"
	@echo "  A64_HOOK_DEBUG   - Enable debug build if set"
	@echo "  ANDROID_KERNEL   - Enable Android-specific tweaks if set"
	@echo "  IOS_KERNEL       - Enable iOS-specific tweaks if set"
	@echo ""
	@echo "Examples:"
	@echo "  make KERNELDIR=~/android-kernel/out"
	@echo "  make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64"
	@echo "  make ANDROID_KERNEL=1 KERNELDIR=~/aosp/common"
	@echo ""

ifdef KERNELDIR
MODDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
all modules:
	$(MAKE) -C $(KERNELDIR) M=$(MODDIR) modules \
		ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)

install:
	$(MAKE) -C $(KERNELDIR) M=$(MODDIR) modules_install \
		ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)

else
all modules:
	@echo "ERROR: KERNELDIR not set."
	@echo "Usage: make KERNELDIR=/path/to/kernel/build/directory"
	@echo "Or run 'make help' for more information."
	@exit 1
endif

.PHONY: all modules clean test help install
