CC := gcc
CFLAGS := -Wall -Wextra -g -O2
INCLUDES := -I..
LDFLAGS := -L..

TARGET := vulkan_overlay
SRCS := vulkan_overlay.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS) ../liba64hook.c ../liba64hook.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< ../liba64hook.c -lpthread

clean:
	rm -f $(TARGET) $(TARGET).arm64
