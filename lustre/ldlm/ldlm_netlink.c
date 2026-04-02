// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * LDLM netlink family — lock namespace stats via genetlink.
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/generic-radix-tree.h>
#include <lustre_compat/net/linux-net.h>

#include <lustre_dlm.h>
#include <lustre_kernelcomm.h>
#include <obd_class.h>

static struct genl_family ldlm_family;

static struct ln_key_list ldlm_list = {
	.lkl_maxattr			= LUSTRE_LDLM_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_LDLM_ATTR_HDR]	= {
			.lkp_value		= "ldlm",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_LDLM_ATTR_NAMESPACE]	= {
			.lkp_value		= "namespace",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_LDLM_ATTR_CONTENDED_LOCKS] = {
			.lkp_value		= "contended_locks",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_LDLM_ATTR_CONTENTION_SECONDS] = {
			.lkp_value		= "contention_seconds",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_LDLM_ATTR_MAX_NOLOCK_BYTES] = {
			.lkp_value		= "max_nolock_bytes",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_LDLM_ATTR_MAX_PARALLEL_AST] = {
			.lkp_value		= "max_parallel_ast",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_LDLM_ATTR_LRU_SIZE]	= {
			.lkp_value		= "lru_size",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_LDLM_ATTR_LRU_MAX]	= {
			.lkp_value		= "lru_max",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_LDLM_ATTR_LRU_MAX_AGE]	= {
			.lkp_value		= "lru_max_age",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_LDLM_ATTR_TIMEOUTS]	= {
			.lkp_value		= "timeouts",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_LDLM_ATTR_LOCK_STATS]	= {
			.lkp_key_format		= LNKF_FLOW | LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED,
		},
	},
};

struct ldlm_entry {
	char				le_namespace[MAX_OBD_NAME];
	struct obd_device		*le_obd;
	struct ldlm_namespace		*le_ns;
};

struct ldlm_ctx {
	struct lustre_nl_ctx		base;
	GENRADIX(struct ldlm_entry)	list;
};

static const char *ldlm_filter_target(struct obd_device *obd)
{
	struct ldlm_namespace *ns = obd->obd_namespace;

	return ns ? ns->ns_name : NULL;
}

static int ldlm_collect(struct lustre_nl_ctx *base, struct obd_device *obd)
{
	struct ldlm_ctx *ctx = container_of(base, struct ldlm_ctx, base);
	struct ldlm_namespace *ns = obd->obd_namespace;
	struct ldlm_entry *entry;

	if (!ns)
		return 0;

	entry = genradix_ptr_alloc(&ctx->list, ctx->base.count++,
				   GFP_ATOMIC);
	if (!entry) {
		ctx->base.count--;
		return -ENOMEM;
	}

	strscpy(entry->le_namespace, ns->ns_name,
		sizeof(entry->le_namespace));
	entry->le_obd = obd;
	entry->le_ns = ns;
	class_incref(obd, "netlink_ldlm", current);
	return 0;
}

static void ldlm_release(void *ventry)
{
	struct ldlm_entry *entry = ventry;

	if (entry->le_obd)
		class_decref(entry->le_obd, "netlink_ldlm", current);
}

static int ldlm_dump_one(struct sk_buff *msg, void *ventry, bool first)
{
	struct ldlm_entry *entry = ventry;
	struct ldlm_namespace *ns = entry->le_ns;

	if (first) {
		int rc = nla_put_string(msg,
					LUSTRE_LDLM_ATTR_HDR, "");
		if (rc)
			return rc;
	}

	if (nla_put_string(msg, LUSTRE_LDLM_ATTR_NAMESPACE,
			   entry->le_namespace) ||
	    nla_put_u32(msg, LUSTRE_LDLM_ATTR_CONTENDED_LOCKS,
			ns->ns_contended_locks) ||
	    nla_put_u32(msg, LUSTRE_LDLM_ATTR_CONTENTION_SECONDS,
			ns->ns_contention_time) ||
	    nla_put_u32(msg, LUSTRE_LDLM_ATTR_MAX_NOLOCK_BYTES,
			ns->ns_max_nolock_size) ||
	    nla_put_u32(msg, LUSTRE_LDLM_ATTR_MAX_PARALLEL_AST,
			ns->ns_max_parallel_ast) ||
	    nla_put_u32(msg, LUSTRE_LDLM_ATTR_LRU_SIZE,
			ns->ns_nr_unused) ||
	    nla_put_u32(msg, LUSTRE_LDLM_ATTR_LRU_MAX,
			ns->ns_max_unused) ||
	    nla_put_u64_64bit(msg, LUSTRE_LDLM_ATTR_LRU_MAX_AGE,
			      ktime_divns(ns->ns_max_age, NSEC_PER_SEC),
			      LUSTRE_LDLM_ATTR_PAD) ||
	    nla_put_u32(msg, LUSTRE_LDLM_ATTR_TIMEOUTS,
			ns->ns_timeouts))
		return -EMSGSIZE;

	return lustre_nl_put_dataset(msg, ns->ns_stats,
				     LUSTRE_LDLM_ATTR_LOCK_STATS);
}

static const struct ln_key_list *ldlm_keys[] = {
	&ldlm_list, &stats_dataset_list, NULL
};

static const struct lustre_nl_obd_ops ldlm_ops = {
	.refname	= "netlink_ldlm",
	.filter_key	= "namespace",
	.family		= &ldlm_family,
	.entry_size	= sizeof(struct ldlm_entry),
	.ctx_size	= sizeof(struct ldlm_ctx),
	.list_offset	= offsetof(struct ldlm_ctx, list),
	.cmd		= LDLM_NL_CMD_STATS,
	.keys		= ldlm_keys,
	.filter_target	= ldlm_filter_target,
	.collect	= ldlm_collect,
	.release	= ldlm_release,
	.dump_one	= ldlm_dump_one,
};

static int lustre_ldlm_start(struct netlink_callback *cb)
{
	return lustre_obd_nl_start(cb, &ldlm_ops);
}

static int lustre_ldlm_dump(struct sk_buff *msg,
			    struct netlink_callback *cb)
{
	return lustre_obd_nl_dump(msg, cb);
}

static int lustre_ldlm_done(struct netlink_callback *cb)
{
	return lustre_obd_nl_done(cb);
}

/* "ldlm" genetlink family */

static const struct genl_multicast_group ldlm_mcast_grps[] = {
	{ .name = "ldlm" },
};

static const struct genl_ops ldlm_genl_ops[] = {
	{
		.cmd	= LDLM_NL_CMD_STATS,
		.start	= lustre_ldlm_start,
		.dumpit	= lustre_ldlm_dump,
		.done	= lustre_ldlm_done,
	},
};

static struct genl_family ldlm_family = {
	.name		= LDLM_GENL_NAME,
	.version	= LDLM_GENL_VERSION,
	.module		= THIS_MODULE,
	.ops		= ldlm_genl_ops,
	.n_ops		= ARRAY_SIZE(ldlm_genl_ops),
	.mcgrps		= ldlm_mcast_grps,
	.n_mcgrps	= ARRAY_SIZE(ldlm_mcast_grps),
#ifdef GENL_FAMILY_HAS_RESV_START_OP
	.resv_start_op	= __LDLM_NL_CMD_MAX_PLUS_ONE,
#endif
};

int ldlm_netlink_init(void)
{
	return genl_register_family(&ldlm_family);
}

void ldlm_netlink_fini(void)
{
	genl_unregister_family(&ldlm_family);
}
