// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <net/sock.h>
#include <linux/uio.h>
#include <linux/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/list.h>

#include <linux/sysctl.h>
#include <linux/debugfs.h>
#include <asm/div64.h>

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include <lnet/lib-lnet.h>
#include <uapi/linux/lustre/lustre_ver.h>

int __init libcfs_init(void)
{
	int rc;

	rc = lustre_symbols_init();
	if (rc < 0) {
		pr_warn("lustre_symbols_init: error %d\n", rc);
		return rc;
	}

	rc = cfs_arch_init();
	if (rc < 0) {
		pr_warn("cfs_arch_init: error %d\n", rc);
		return rc;
	}

	return 0;
}

void __exit libcfs_exit(void)
{
	cfs_arch_exit();
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre helper library");
MODULE_VERSION(LIBCFS_VERSION);
MODULE_LICENSE("GPL");

module_init(libcfs_init);
module_exit(libcfs_exit);
