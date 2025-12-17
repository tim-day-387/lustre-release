# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

subdir-ccflags-y := -include $(lsrctree)/undef.h
subdir-ccflags-y += -include $(lsrctree)/config.h
subdir-ccflags-y += -I$(lsrctree)/include

subdir-ccflags-y += $(call cc-option, -Wno-format-truncation)
subdir-ccflags-y += $(call cc-option, -Wno-stringop-truncation)
subdir-ccflags-y += $(call cc-option, -Wno-stringop-overflow)

crypto-ccflags := -I$(lsrctree)/lnet/include
crypto-ccflags += -I$(lsrctree)/lnet/include/uapi
crypto-ccflags += -I$(lsrctree)/lustre/include
crypto-ccflags += -I$(lsrctree)/lustre/include/uapi

obj-m += libcfs.o

libcfs-objs += module.o misc.o symbols.o
CFLAGS_misc.o := $(crypto-ccflags)

libcfs-crypto-objs := fs/crypto/crypto.o
CFLAGS_fs/crypto/crypto.o := $(crypto-ccflags)
libcfs-crypto-objs += fs/crypto/fname.o
CFLAGS_fs/crypto/fname.o := $(crypto-ccflags)
libcfs-crypto-objs += fs/crypto/hkdf.o
CFLAGS_fs/crypto/hkdf.o := $(crypto-ccflags)
libcfs-crypto-objs += fs/crypto/hooks.o
CFLAGS_fs/crypto/hooks.o := $(crypto-ccflags)
libcfs-crypto-objs += fs/crypto/keyring.o
CFLAGS_fs/crypto/keyring.o := $(crypto-ccflags)
libcfs-crypto-objs += fs/crypto/keysetup.o
CFLAGS_fs/crypto/keysetup.o := $(crypto-ccflags)
libcfs-crypto-objs += fs/crypto/keysetup_v1.o
CFLAGS_fs/crypto/keysetup_v1.o := $(crypto-ccflags)
libcfs-crypto-objs += fs/crypto/policy.o
CFLAGS_fs/crypto/policy.o := $(crypto-ccflags)

libcfs-objs += $(libcfs-crypto-objs)

libcfs-lib-objs := glob.o generic-radix-tree.o
libcfs-lib-objs := $(addprefix lib/,$(libcfs-lib-objs))
libcfs-objs += $(libcfs-lib-objs)

libcfs-mm-objs := shrinker_debug.o vmalloc.o
libcfs-mm-objs := $(addprefix mm/,$(libcfs-mm-objs))
libcfs-objs += $(libcfs-mm-objs)

libcfs-sched-objs := wait.o wait_bit.o
libcfs-sched-objs := $(addprefix kernel/sched/,$(libcfs-sched-objs))
libcfs-objs += $(libcfs-sched-objs)
