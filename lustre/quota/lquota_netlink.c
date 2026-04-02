// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lquota genetlink family -- quota limits and accounting data via
 * generic netlink.  The collection functions live in qmt_netlink.c
 * (global quota) and qsd_netlink.c (per-ID accounting); this file
 * provides the family registration and start/dump/done handlers.
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <linux/generic-radix-tree.h>
#include <lustre_compat/net/linux-net.h>

#include <lnet/lib-lnet.h>
#include <lustre_kernelcomm.h>
#include <obd_class.h>

#include "lquota_internal.h"

/* Forward declaration for lquota family (defined at bottom of file) */
static struct genl_family lquota_family;

/* ---- Context and helpers ---- */

struct genl_quota_list {
	quota_nl_radix_t		gql_list;
	unsigned int			gql_index;
	unsigned int			gql_count;
	bool				gql_key_sent;
};

static inline struct genl_quota_list *
quota_dump_ctx(struct netlink_callback *cb)
{
	return (struct genl_quota_list *)cb->args[0];
}

/* ---- Key list ---- */

static struct ln_key_list quota_list = {
	.lkl_maxattr			= LUSTRE_QUOTA_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_QUOTA_ATTR_HDR]		= {
			.lkp_value		= "quota",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_QUOTA_ATTR_SOURCE]	= {
			.lkp_value		= "source",
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_QUOTA_ATTR_RECORD_TYPE]	= {
			.lkp_value		= "record_type",
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_QUOTA_ATTR_POOL]	= {
			.lkp_value		= "pool",
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_QUOTA_ATTR_MANAGER]	= {
			.lkp_value		= "manager",
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_QUOTA_ATTR_QTYPE]	= {
			.lkp_value		= "qtype",
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_QUOTA_ATTR_ID]		= {
			.lkp_value		= "id",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_QUOTA_ATTR_HARDLIMIT]	= {
			.lkp_value		= "hardlimit",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_QUOTA_ATTR_SOFTLIMIT]	= {
			.lkp_value		= "softlimit",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_QUOTA_ATTR_GRANTED]	= {
			.lkp_value		= "granted",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_QUOTA_ATTR_KBYTES]	= {
			.lkp_value		= "kbytes",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_QUOTA_ATTR_INODES]	= {
			.lkp_value		= "inodes",
			.lkp_data_type		= NLA_U64,
		},
	},
};

/* ---- Handlers ---- */

static int lquota_nl_start(struct netlink_callback *cb)
{
	struct netlink_ext_ack *extack = cb->extack;
	struct genl_quota_list *qlist;
	int rc;

	ENTRY;

	LIBCFS_ALLOC(qlist, sizeof(*qlist));
	if (!qlist) {
		NL_SET_ERR_MSG(extack, "failed to setup quota list");
		RETURN(-ENOMEM);
	}
	genradix_init(&qlist->gql_list);
	qlist->gql_index = 0;
	qlist->gql_count = 0;
	cb->args[0] = (long)qlist;

	/* Collect QMT global quota entries directly */
	rc = lustre_quota_nl_collect(&qlist->gql_list, &qlist->gql_count);
	if (rc < 0)
		GOTO(err_free, rc);

	/* Append per-ID accounting records from QSD slaves */
	rc = lustre_quota_acct_nl_collect(&qlist->gql_list, &qlist->gql_count);
	if (rc < 0)
		GOTO(err_free, rc);

	RETURN(0);

err_free:
	genradix_free(&qlist->gql_list);
	LIBCFS_FREE(qlist, sizeof(*qlist));
	cb->args[0] = 0;
	RETURN(rc);
}

static int lquota_nl_dump(struct sk_buff *msg, struct netlink_callback *cb)
{
	struct genl_quota_list *qlist = quota_dump_ctx(cb);
	struct netlink_ext_ack *extack = cb->extack;
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int rc = 0;

	if (!qlist)
		return 0;

	if (!qlist->gql_key_sent) {
		const struct ln_key_list *all[] = { &quota_list, NULL };

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&lquota_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LQUOTA_NL_CMD_QUOTA, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack,
				       "failed to send quota key table");
			return rc;
		}
		qlist->gql_key_sent = true;
	}

	while (qlist->gql_index < qlist->gql_count) {
		struct quota_nl_entry *entry;
		void *hdr;

		entry = genradix_ptr(&qlist->gql_list, qlist->gql_index);
		if (!entry) {
			qlist->gql_index++;
			continue;
		}

		hdr = genlmsg_put(msg, portid, seq, &lquota_family,
				  NLM_F_MULTI, LQUOTA_NL_CMD_QUOTA);
		if (!hdr) {
			rc = -EMSGSIZE;
			break;
		}

		if (qlist->gql_index == 0)
			rc = nla_put_string(msg, LUSTRE_QUOTA_ATTR_HDR, "");
		if (rc < 0 ||
		    nla_put_string(msg, LUSTRE_QUOTA_ATTR_SOURCE,
				   entry->qne_source) ||
		    nla_put_string(msg, LUSTRE_QUOTA_ATTR_RECORD_TYPE,
				   entry->qne_record_type) ||
		    nla_put_string(msg, LUSTRE_QUOTA_ATTR_POOL,
				   entry->qne_pool) ||
		    nla_put_string(msg, LUSTRE_QUOTA_ATTR_MANAGER,
				   entry->qne_manager) ||
		    nla_put_string(msg, LUSTRE_QUOTA_ATTR_QTYPE,
				   entry->qne_qtype) ||
		    nla_put_u64_64bit(msg, LUSTRE_QUOTA_ATTR_ID,
				      entry->qne_id,
				      LUSTRE_QUOTA_ATTR_PAD)) {
			genlmsg_cancel(msg, hdr);
			rc = -EMSGSIZE;
			break;
		}

		if (strcmp(entry->qne_record_type, "global") == 0) {
			if (nla_put_u64_64bit(msg,
					      LUSTRE_QUOTA_ATTR_HARDLIMIT,
					      entry->qne_hardlimit,
					      LUSTRE_QUOTA_ATTR_PAD) ||
			    nla_put_u64_64bit(msg,
					      LUSTRE_QUOTA_ATTR_SOFTLIMIT,
					      entry->qne_softlimit,
					      LUSTRE_QUOTA_ATTR_PAD) ||
			    nla_put_u64_64bit(msg,
					      LUSTRE_QUOTA_ATTR_GRANTED,
					      entry->qne_granted,
					      LUSTRE_QUOTA_ATTR_PAD)) {
				genlmsg_cancel(msg, hdr);
				rc = -EMSGSIZE;
				break;
			}
		} else {
			if (nla_put_u64_64bit(msg,
					      LUSTRE_QUOTA_ATTR_KBYTES,
					      entry->qne_kbytes,
					      LUSTRE_QUOTA_ATTR_PAD) ||
			    nla_put_u64_64bit(msg,
					      LUSTRE_QUOTA_ATTR_INODES,
					      entry->qne_inodes,
					      LUSTRE_QUOTA_ATTR_PAD)) {
				genlmsg_cancel(msg, hdr);
				rc = -EMSGSIZE;
				break;
			}
		}

		genlmsg_end(msg, hdr);
		qlist->gql_index++;
	}

	return rc;
}

static int lquota_nl_done(struct netlink_callback *cb)
{
	struct genl_quota_list *qlist = quota_dump_ctx(cb);

	if (qlist) {
		genradix_free(&qlist->gql_list);
		LIBCFS_FREE(qlist, sizeof(*qlist));
		cb->args[0] = 0;
	}

	return 0;
}

/* ---- Family infrastructure ---- */

static const struct genl_multicast_group lquota_mcast_grps[] = {
	{ .name = "quota" },
};

static const struct genl_ops lquota_genl_ops[] = {
	{
		.cmd	= LQUOTA_NL_CMD_QUOTA,
		.start	= lquota_nl_start,
		.dumpit	= lquota_nl_dump,
		.done	= lquota_nl_done,
	},
};

static struct genl_family lquota_family = {
	.name		= LQUOTA_GENL_NAME,
	.version	= LQUOTA_GENL_VERSION,
	.module		= THIS_MODULE,
	.ops		= lquota_genl_ops,
	.n_ops		= ARRAY_SIZE(lquota_genl_ops),
	.mcgrps		= lquota_mcast_grps,
	.n_mcgrps	= ARRAY_SIZE(lquota_mcast_grps),
#ifdef GENL_FAMILY_HAS_RESV_START_OP
	.resv_start_op	= __LQUOTA_NL_CMD_MAX_PLUS_ONE,
#endif
};

int lquota_netlink_init(void)
{
	return genl_register_family(&lquota_family);
}

void lquota_netlink_fini(void)
{
	genl_unregister_family(&lquota_family);
}
