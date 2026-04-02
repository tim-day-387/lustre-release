// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Quota netlink collection -- iterate QMT global index objects and
 * populate a genradix of struct quota_nl_entry for the lquota genetlink
 * family dump handler in lquota_netlink.c.
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <lustre_kernelcomm.h>
#include <obd_class.h>

#include "qmt_internal.h"

/*
 * Iterate one global index object (one pool x one quota type) and
 * append entries to @radix.  The object stores lquota_glb_rec records
 * keyed by 64-bit quota ID.
 */
static int quota_collect_glb_obj(const struct lu_env *env,
				 struct dt_object *obj, const char *source,
				 const char *pool, const char *manager,
				 const char *qtype, quota_nl_radix_t *radix,
				 unsigned int *count)
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
		struct dt_key *key;
		struct lquota_glb_rec *rec;
		struct quota_nl_entry *entry;
		union lquota_rec qrec;

		key = iops->key(env, it);
		if (IS_ERR(key)) {
			rc = PTR_ERR(key);
			break;
		}

		rc = iops->rec(env, it, (struct dt_rec *)&qrec, 0);
		if (rc)
			break;

		rec = &qrec.lqr_glb_rec;

		/* skip IDs with no limits and no grant */
		if (rec->qbr_hardlimit == 0 && rec->qbr_softlimit == 0 &&
		    rec->qbr_granted == 0)
			goto next;

		entry = genradix_ptr_alloc(radix, *count, GFP_KERNEL);
		if (!entry) {
			rc = -ENOMEM;
			break;
		}

		strscpy(entry->qne_source, source, sizeof(entry->qne_source));
		strscpy(entry->qne_record_type, "global",
			sizeof(entry->qne_record_type));
		strscpy(entry->qne_pool, pool, sizeof(entry->qne_pool));
		strscpy(entry->qne_manager, manager,
			sizeof(entry->qne_manager));
		strscpy(entry->qne_qtype, qtype, sizeof(entry->qne_qtype));
		entry->qne_id = *((__u64 *)key);
		entry->qne_hardlimit = rec->qbr_hardlimit;
		entry->qne_softlimit = rec->qbr_softlimit;
		entry->qne_granted = rec->qbr_granted;
		entry->qne_kbytes = 0;
		entry->qne_inodes = 0;

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
 * Walk all OBD devices looking for QMT instances, iterate their pool
 * list, and collect global quota entries into @list.
 *
 * Returns 0 on success, negative errno on failure.
 */
int lustre_quota_nl_collect(quota_nl_radix_t *list, unsigned int *count)
{
	quota_nl_radix_t *radix = list;
	int dev_count = class_obd_devs_count();
	struct lu_env env;
	int rc;
	int i;

	ENTRY;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc) {
		CERROR("lu_env_init failed: rc = %d\n", rc);
		RETURN(rc);
	}

	for (i = 0; i < dev_count; i++) {
		struct obd_device *obd = class_num2obd(i);
		struct qmt_device *qmt;
		struct qmt_pool_info *pool;

		if (!obd || obd->obd_stopping)
			continue;

		if (!test_bit(OBDF_SET_UP, obd->obd_flags))
			continue;

		if (strcmp(obd->obd_type->typ_name, LUSTRE_QMT_NAME) != 0)
			continue;

		qmt = lu2qmt_dev(obd->obd_lu_dev);
		if (!qmt)
			continue;

		down_read(&qmt->qmt_pool_lock);
		list_for_each_entry(pool, &qmt->qmt_pool_list,
				    qpi_linkage) {
			const char *manager;
			const char *pool_name;
			int qtype;

			if (pool->qpi_rtype == LQUOTA_RES_MD)
				manager = "md";
			else
				manager = "dt";

			pool_name = pool->qpi_name;

			for (qtype = 0; qtype < LL_MAXQUOTAS; qtype++) {
				struct dt_object *glb_obj;

				glb_obj = pool->qpi_glb_obj[qtype];
				if (!glb_obj)
					continue;

				rc = quota_collect_glb_obj(
					&env, glb_obj, qmt->qmt_svname,
					pool_name, manager,
					qtype_name(qtype), radix, count);
				if (rc) {
					up_read(&qmt->qmt_pool_lock);
					goto out;
				}
			}
		}
		up_read(&qmt->qmt_pool_lock);
	}

	rc = 0;
out:
	lu_env_fini(&env);
	RETURN(rc);
}

