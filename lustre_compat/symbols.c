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

static void *cfs_kallsyms_lookup_name(const char *name)
{
	return __cfs_kallsyms_lookup_name(name);
}

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

#ifndef HAVE_FLUSH_DELAYED_FPUT
static void (*__flush_delayed_fput)(void);

void flush_delayed_fput(void)
{
	__flush_delayed_fput();
}
EXPORT_SYMBOL_GPL(flush_delayed_fput);
#endif

#if !defined(FOLIO_MEMCG_LOCK_EXPORTED) && defined(HAVE_FOLIO_MEMCG_LOCK)
void (*__folio_memcg_lock)(struct folio *folio);

void folio_memcg_lock(struct folio *folio)
{
	__folio_memcg_lock(folio);
}
EXPORT_SYMBOL_GPL(folio_memcg_lock);

void (*__folio_memcg_unlock)(struct folio *folio);

void folio_memcg_unlock(struct folio *folio)
{
	__folio_memcg_unlock(folio);
}
EXPORT_SYMBOL_GPL(folio_memcg_unlock);
#endif

static int (*__apply_workqueue_attrs)(struct workqueue_struct *wq,
					  const struct workqueue_attrs *attrs);

int apply_workqueue_attrs(struct workqueue_struct *wq,
			      const struct workqueue_attrs *attrs)
{
	return __apply_workqueue_attrs(wq, attrs);
}
EXPORT_SYMBOL_GPL(apply_workqueue_attrs);

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

#ifndef HAVE_FLUSH_DELAYED_FPUT
	__flush_delayed_fput = cfs_kallsyms_lookup_name("flush_delayed_fput");
	if (!__flush_delayed_fput)
		return -EINVAL;
#endif

#if !defined(FOLIO_MEMCG_LOCK_EXPORTED) && defined(HAVE_FOLIO_MEMCG_LOCK)
	__folio_memcg_lock = cfs_kallsyms_lookup_name("folio_memcg_lock");
	if (!__folio_memcg_lock)
		return -EINVAL;

	__folio_memcg_unlock = cfs_kallsyms_lookup_name("folio_memcg_unlock");
	if (!__folio_memcg_unlock)
		return -EINVAL;
#endif

	__apply_workqueue_attrs = cfs_kallsyms_lookup_name("apply_workqueue_attrs");
	if (!__apply_workqueue_attrs)
		return -EINVAL;

	return 0;
}
