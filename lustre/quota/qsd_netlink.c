// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * QSD (Quota Slave Device) accounting collection for generic netlink.
 * Iterates all QSD instances, walks per-ID accounting index objects,
 * and populates struct quota_nl_entry records for the lquota genetlink
 * family dump handler in lquota_netlink.c.
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <lustre_kernelcomm.h>
#include <obd_class.h>

#include "qsd_internal.h"

/*
 * Iterate one accounting index object (one qtype on one QSD) and
 * append per-ID usage entries to @radix.
 *
 * The index is keyed by 64-bit quota ID with lquota_acct_rec values
 * containing bspace (bytes) and ispace (inodes).
 */
static int qsd_collect_acct_obj(const struct lu_env *env,
				struct dt_object *obj, const char *source,
				const char *manager, const char *qtype,
				quota_nl_radix_t *radix, unsigned int *count)
{
	const struct dt_it_ops *iops;
	struct dt_it *it;
	int rc;

	if (!obj || !dt_object_exists(obj))
		return 0;

	if (!obj->do_index_ops)
		return 0;

	iops = &obj->do_index_ops->dio_it;
	it = iops->init(env, obj, 0);
	if (IS_ERR(it))
		return PTR_ERR(it);

	rc = iops->load(env, it, 0);
	if (rc == 0)
		rc = iops->next(env, it);
	else if (rc > 0)
		rc = 0; /* positioned on first record */

	while (rc == 0) {
		struct lquota_acct_rec *rec;
		struct quota_nl_entry *entry;
		union lquota_rec qrec;
		struct dt_key *key;

		key = iops->key(env, it);
		if (IS_ERR(key)) {
			rc = PTR_ERR(key);
			break;
		}

		rc = iops->rec(env, it, (struct dt_rec *)&qrec, 0);
		if (rc)
			break;

		rec = &qrec.lqr_acct_rec;

		/* skip IDs with no usage */
		if (rec->bspace == 0 && rec->ispace == 0)
			goto next;

		entry = genradix_ptr_alloc(radix, *count, GFP_KERNEL);
		if (!entry) {
			rc = -ENOMEM;
			break;
		}

		strscpy(entry->qne_source, source, sizeof(entry->qne_source));
		strscpy(entry->qne_record_type, "acct",
			sizeof(entry->qne_record_type));
		entry->qne_pool[0] = '\0';
		strscpy(entry->qne_manager, manager,
			sizeof(entry->qne_manager));
		strscpy(entry->qne_qtype, qtype, sizeof(entry->qne_qtype));
		entry->qne_id = *((__u64 *)key);
		entry->qne_hardlimit = 0;
		entry->qne_softlimit = 0;
		entry->qne_granted = 0;
		entry->qne_kbytes = stoqb(rec->bspace);
		entry->qne_inodes = rec->ispace;

		(*count)++;
next:
		rc = iops->next(env, it);
	}

	iops->put(env, it);
	iops->fini(env, it);

	/* next() returns +1 at end of index, not an error */
	if (rc > 0)
		rc = 0;

	return rc;
}

/*
 * Collect one QSD instance's accounting data for all quota types.
 */
static int qsd_collect_one(const struct lu_env *env,
			   struct qsd_instance *qsd,
			   quota_nl_radix_t *radix, unsigned int *count)
{
	const char *manager = qsd->qsd_is_md ? "md" : "dt";
	int qtype;
	int rc = 0;

	for (qtype = 0; qtype < LL_MAXQUOTAS; qtype++) {
		struct qsd_qtype_info *qqi = qsd->qsd_type_array[qtype];

		if (!qqi || !qqi->qqi_acct_obj)
			continue;

		rc = qsd_collect_acct_obj(env, qqi->qqi_acct_obj,
					  qsd->qsd_svname, manager,
					  qtype_name(qtype), radix, count);
		if (rc)
			break;
	}

	return rc;
}

/*
 * Walk all QSD instances via qfs_list and collect per-ID accounting
 * records into @list.
 *
 * Locking strategy: take qfs_list_lock to snapshot fsinfo pointers
 * (bumping refcounts), then release the spinlock before doing the
 * actual iteration which may sleep (dt_it ops hit disk).
 */
/*
 * Maximum number of qsd_fsinfo entries we expect.  Typically one per
 * filesystem, so 16 is generous.
 */
#define QFS_SNAP_MAX	16

int lustre_quota_acct_nl_collect(quota_nl_radix_t *list, unsigned int *count)
{
	quota_nl_radix_t *radix = list;
	struct qsd_fsinfo *snap[QFS_SNAP_MAX];
	struct qsd_fsinfo *qfs;
	unsigned int nsnap = 0;
	struct lu_env env;
	int rc;
	int i;

	ENTRY;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc) {
		CERROR("lu_env_init failed: rc = %d\n", rc);
		RETURN(rc);
	}

	/* Snapshot fsinfo pointers under spinlock, bump refcounts */
	spin_lock(&qfs_list_lock);
	list_for_each_entry(qfs, &qfs_list, qfs_link) {
		if (nsnap >= QFS_SNAP_MAX) {
			CWARN("quota: more than %d filesystems, some omitted\n",
			      QFS_SNAP_MAX);
			break;
		}
		qfs->qfs_ref++;
		snap[nsnap++] = qfs;
	}
	spin_unlock(&qfs_list_lock);

	/* Iterate without holding spinlock -- dt_it ops may sleep */
	for (i = 0; i < nsnap && rc == 0; i++) {
		struct qsd_instance *qsd;

		mutex_lock(&snap[i]->qfs_mutex);
		list_for_each_entry(qsd, &snap[i]->qfs_qsd_list,
				    qsd_link) {
			if (qsd->qsd_stopping || !qsd->qsd_prepared)
				continue;

			rc = qsd_collect_one(&env, qsd, radix, count);
			if (rc)
				break;
		}
		mutex_unlock(&snap[i]->qfs_mutex);
	}

	/* Drop references */
	spin_lock(&qfs_list_lock);
	for (i = 0; i < nsnap; i++)
		snap[i]->qfs_ref--;
	spin_unlock(&qfs_list_lock);

	lu_env_fini(&env);
	RETURN(rc);
}

