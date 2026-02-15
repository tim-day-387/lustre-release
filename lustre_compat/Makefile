# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m := libcfs.o

# Core objects
libcfs-y := module.o symbols.o misc.o

# Compat: kernel/sched
include $(src)/kernel/sched/Makefile
libcfs-y += $(patsubst %,kernel/sched/%,$(sched_objs))

# Compat: fs/crypto (conditional on CONFIG_LL_ENCRYPTION)
include $(src)/fs/crypto/Makefile
ifneq ($(shell grep -c 'define CONFIG_LL_ENCRYPTION 1' $(src)/../config.h 2>/dev/null),0)
libcfs-y += $(patsubst %,fs/crypto/%,$(fscrypt_objs))
endif

# Compat: mm
include $(src)/mm/Makefile
libcfs-y += $(patsubst %,mm/%,$(mm_objs))

# Compat: lib
include $(src)/lib/Makefile
libcfs-y += $(patsubst %,lib/%,$(lib_objs))

# Debug objects
ifdef COMPAT_LIBCFS_CDEBUG
libcfs-y += ../debug/module.o ../debug/debug.o ../debug/fail.o ../debug/tracefile.o
endif
