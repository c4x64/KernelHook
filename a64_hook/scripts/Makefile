CROSS   ?=
CC       = $(CROSS)gcc
AR       = $(CROSS)ar
CFLAGS   = -Wall -Wextra -Werror -O2 -fPIC
LDFLAGS  = -lpthread

SRC      = liba64hook.c
OBJ      = liba64hook.o
LIB      = liba64hook.a
TEST     = a64_hook_test

ifneq ($(BUILD_VULKAN),)
CFLAGS  += -DBUILD_VULKAN=1
endif

.PHONY: all clean android

all: $(LIB) $(TEST)

$(OBJ): $(SRC) liba64hook.h
	$(CC) $(CFLAGS) -c -o $@ $(SRC)

$(LIB): $(OBJ)
	$(AR) rcs $@ $^

$(TEST): liba64hook_test.c $(LIB) liba64hook.h
	$(CC) $(CFLAGS) -o $@ liba64hook_test.c -L. -la64hook $(LDFLAGS)

android:
	$(MAKE) CROSS=aarch64-linux-android21- CC=clang AR=llvm-ar \
		CFLAGS="-Wall -Wextra -Werror -O2 -fPIC --sysroot=$(NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/sysroot" \
		all

clean:
	rm -f $(OBJ) $(LIB) $(TEST)
