# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# Author: Timothy Day <timday@amazon.com>
#

# Tools
CLANG ?= clang-20
LLVM_STRIP ?= llvm-strip-20
BPFTOOL ?= bpftool
CC := $(CLANG)

# Paths
LUSTRE := /home/timothy/Programming/lustre-release/
LUSTRE_VERSION_FILE := /home/timothy/Programming/lustre-release/LUSTRE-VERSION-FILE
BUILD := /tmp/ktest-out/kernel_build.x86_64/

# Lustre includes
LUSTRE_INCLUDES := -include$(LUSTRE)/utils/lnetdump/lnettypes.h
LUSTRE_UAPI_INCLUDES := -I/home/timothy/Programming/lustre-release/lustre/include/uapi/ \
	-I/home/timothy/Programming/lustre-release/lnet/include/uapi/

# eBPF kernel code
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -D__KERNEL__ -nostdinc -I$(BUILD)/tools/bpf/resolve_btfids/libbpf/include/

# libbpf userspace code
LIBBPF_LIBS := $(BUILD)/tools/bpf/resolve_btfids/libbpf/libbpf.a -lelf -lz
LIBBPF_CFLAGS := -O2 -g \
	-Wno-address-of-packed-member \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wunused-variable \
	-ferror-limit=99 \
	$(LUSTRE_UAPI_INCLUDES) \
	-I$(BUILD)/tools/bpf/resolve_btfids/libbpf/include/

# Lustre version
LUSTRE_VERSION := $(shell sed -n -e 's/^LUSTRE_VERSION = //p' $(LUSTRE_VERSION_FILE))
LUSTRE_VERSION_CFLAGS := -DLUSTRE_VERSION_STRING=\"$(LUSTRE_VERSION)\"

.PHONY: all clean

all: lnetdump

btf-info: bpftool-merge
	if [ -f /sys/kernel/btf/lnet ]; then \
		bpftool btf dump file /sys/kernel/btf/lnet format c > lnettypes.h; \
	else \
		cp $(LUSTRE)/lnet/lnet/lnet.ko lnet.ko.tmp; \
		pahole -J lnet.ko.tmp; \
		./bpftool-merge $(BUILD)/vmlinux lnet.ko.tmp merged.btf; \
		bpftool btf dump file merged.btf format c > lnettypes.h; \
	fi

lnetdump.skel.h: lnetdump.bpf.o
	$(BPFTOOL) gen skeleton lnetdump.bpf.o > lnetdump.skel.h

lnetdump.bpf.o: lnetdump.bpf.c btf-info
	$(CC) $(LUSTRE_INCLUDES) $(BPF_CFLAGS) -c $< -o $@

bpftool-merge: bpftool-merge.c
	$(CC) -O2 -g -Wall -o bpftool-merge bpftool-merge.c -lbpf

LNETDUMP := \
	lnetdump.c \
	pack.c \
	layout.c \
	bpf_input.c \
	print_output.c

lnetdump: $(LNETDUMP) lnetdump.skel.h
	$(CC) $(LIBBPF_CFLAGS) $(LUSTRE_VERSION_CFLAGS) $(LNETDUMP) -o $@ $(LIBBPF_LIBS)

clean:
	rm -f lnetdump.bpf.o lnetdump.o lnetdump bpftool-merge lnetdump.skel.h
