// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (c) 2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Author: Timothy Day <timday@amazon.com>
 */

#include <linux/kprobes.h>

#include <libcfs/libcfs.h>
#include <libcfs/libcfs_debug.h>

static void *(*__cfs_kallsyms_lookup_name)(const char *name);

void *cfs_kallsyms_lookup_name(const char *name)
{
	return __cfs_kallsyms_lookup_name(name);
}
EXPORT_SYMBOL_GPL(cfs_kallsyms_lookup_name);

#ifdef HAVE_KALLSYMS_LOOKUP_NAME
static int find_kallsyms_lookup_name(void)
{
	__cfs_kallsyms_lookup_name = (void *(*)(const char *))kallsyms_lookup_name;

	return 0;
}
#else
static int find_kallsyms_lookup_name(void)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};
	int rc;

	rc = register_kprobe(&kp);
	if (rc < 0)
		return rc;

	__cfs_kallsyms_lookup_name = (void *)kp.addr;
	if (!__cfs_kallsyms_lookup_name)
		return -EINVAL;

	unregister_kprobe(&kp);

	return 0;
}
#endif

#ifndef HAVE_SCHED_SHOW_TASK
static void (*__sched_show_task)(struct task_struct *p);

void sched_show_task(struct task_struct *p)
{
	__sched_show_task(p);
}
EXPORT_SYMBOL_GPL(sched_show_task);
#endif

int lustre_symbols_init(void)
{
	int rc;

	rc = find_kallsyms_lookup_name();
	if (rc < 0)
		return rc;

	if (!cfs_kallsyms_lookup_name("kallsyms_lookup_name"))
		return -EINVAL;

#ifndef HAVE_SCHED_SHOW_TASK
	__sched_show_task = cfs_kallsyms_lookup_name("sched_show_task");
	if (!__sched_show_task)
		return -EINVAL;
#endif

	return 0;
}
