# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += libcfs.o

libcfs-objs += module.o symbols.o misc.o

libcfs-crypto-objs := crypto.o fname.o hkdf.o hooks.o keyring.o
libcfs-crypto-objs += keysetup.o keysetup_v1.o policy.o
libcfs-crypto-objs := $(addprefix crypto/,$(libcfs-crypto-objs))
libcfs-objs += $(libcfs-crypto-objs)

libcfs-lib-objs := xarray.o glob.o generic-radix-tree.o
libcfs-lib-objs := $(addprefix lib/,$(libcfs-lib-objs))
libcfs-objs += $(libcfs-lib-objs)

libcfs-mm-objs := shrinker_debug.o
libcfs-mm-objs := $(addprefix mm/,$(libcfs-mm-objs))
libcfs-objs += $(libcfs-mm-objs)

libcfs-sched-objs := wait.o wait_bit.o
libcfs-sched-objs := $(addprefix kernel/sched/,$(libcfs-sched-objs))
libcfs-objs += $(libcfs-sched-objs)
