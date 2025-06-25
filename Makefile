# Makefile for XDP Drop Example

# Define source and build directories
SRC_DIR := src
BUILD_DIR := build

# Source files
XDP_KERN_SRC := $(SRC_DIR)/xdp_drop_kern.bpf.c
USER_APP_SRC := $(SRC_DIR)/xdp_drop_user.c

# Get target architecture for BPF programs
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_arm64
else
    $(error Unsupported architecture $(ARCH) for BPF compilation. Please add __TARGET_ARCH_xxx manually to BPF_CFLAGS.)
endif

# Include files
LINUX_KERNEL_INCLUDE ?= /usr/src/linux-headers-$(shell uname -r)/include
KERNEL_INCLUDE_PATH ?= /usr/src/linux-headers-$(shell uname -r)/arch/x86/include
ARCH_INCLUDE_PATH := /usr/include/$(shell dpkg-architecture -qDEB_HOST_MULTIARCH)

# Output files
XDP_KERN_OBJ := $(BUILD_DIR)/xdp_drop_kern.bpf.o
USER_APP_BIN := $(BUILD_DIR)/xdp_drop_user

# Compiler flags
CLANG_CFLAGS := -g -O2 -target bpf -I/usr/include/bpf -I$(ARCH_INCLUDE_PATH)
LIBCBPF_CFLAGS := -g -Wall
LIBCBPF_LIBS := -lbfd -lelf -lz # Required for libbpf
LIBS := $(LIBCBPF_LIBS)

# Phony targets
.PHONY: all clean

all: $(BUILD_DIR) $(XDP_KERN_OBJ) $(USER_APP_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(XDP_KERN_OBJ): $(XDP_KERN_SRC)
	clang $(CLANG_CFLAGS) -c $< -o $@

$(USER_APP_BIN): $(USER_APP_SRC)
	$(CC) $(LIBCBPF_CFLAGS) $< -o $@ -lbpf $(LIBS)

clean:
	rm -rf $(BUILD_DIR)
