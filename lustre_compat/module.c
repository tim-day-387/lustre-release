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

#include "module.h"

static int __init libcfs_init(void)
{
	int rc;

	rc = cfs_arch_init();
	if (rc < 0) {
		pr_warn("cfs_arch_init: error %d\n", rc);
		return rc;
	}

	return 0;
}

static void __exit libcfs_exit(void)
{
	cfs_arch_exit();
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre helper library");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");

module_init(libcfs_init);
module_exit(libcfs_exit);
