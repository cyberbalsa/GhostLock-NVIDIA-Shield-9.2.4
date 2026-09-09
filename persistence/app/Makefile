NDK ?= /opt/android-ndk-r29
TOOLCHAIN ?= $(NDK)/toolchains/llvm/prebuilt/linux-x86_64
CC := $(TOOLCHAIN)/bin/aarch64-linux-android30-clang
SYSROOT := $(TOOLCHAIN)/sysroot

BUILD_DIR := build
TARGET := $(BUILD_DIR)/libghostlock_runner.so

CFLAGS := --target=aarch64-linux-android30 --sysroot=$(SYSROOT) \
  -O2 -fPIE -Wall -Wextra

.PHONY: all clean check-ndk

all: check-ndk $(TARGET)

$(TARGET): runner.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -pie $< -o $@

check-ndk:
	@test -x $(CC) || (echo "clang not found: $(CC)" && exit 1)

clean:
	rm -rf $(BUILD_DIR)
