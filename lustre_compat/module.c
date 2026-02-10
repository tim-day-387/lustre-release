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
#include <linux/init.h>

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/libcfs/libcfs.h>
#include <uapi/linux/lustre/lustre_ver.h>

int cpu_npartitions;
EXPORT_SYMBOL(cpu_npartitions);
module_param(cpu_npartitions, int, 0444);
MODULE_PARM_DESC(cpu_npartitions, "# of CPU partitions");

char *cpu_pattern = "N";
EXPORT_SYMBOL(cpu_pattern);
module_param(cpu_pattern, charp, 0444);
MODULE_PARM_DESC(cpu_pattern, "CPU partitions pattern");

static int __init libcfs_init(void)
{
	int rc;

	rc = cfs_arch_init();
	if (rc < 0) {
		CERROR("cfs_arch_init: error %d\n", rc);
		return rc;
	}

	rc = debug_module_init();
	if (rc) {
		cfs_arch_exit();
		return rc;
	}

	return 0;
}

static void __exit libcfs_exit(void)
{
	debug_module_exit();
	cfs_arch_exit();
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre helper library");
MODULE_VERSION(LIBCFS_VERSION);
MODULE_LICENSE("GPL");

module_init(libcfs_init);
module_exit(libcfs_exit);
