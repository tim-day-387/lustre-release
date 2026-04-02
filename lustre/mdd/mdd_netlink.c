// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * MDD genetlink family — changelog user state via generic netlink.
 *
 * Iterates MDD devices and populates genradix arrays of
 * changelog_nl_entry (per-MDT state) and changelog_nl_user
 * (per-consumer state) for the MDD_NL_CMD_CHANGELOG dump handler.
 * This reports changelog consumers, not changelog records.
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/generic-radix-tree.h>
#include <lustre_compat/net/linux-net.h>

#include <lnet/lib-lnet.h>
#include <lustre_kernelcomm.h>
#include <obd_class.h>

#include "mdd_internal.h"

/* Forward declaration for mdd family (defined at bottom of file) */
static struct genl_family mdd_family;

/* ---- Collection helpers ---- */

struct chlg_collect_ctx {
	changelog_user_radix_t	*ccc_users;
	unsigned int	*ccc_nusers;
	int		 ccc_rc;
};

static int changelog_collect_user_cb(const struct lu_env *env,
				     struct llog_handle *llh,
				     struct llog_rec_hdr *hdr, void *data)
{
	struct chlg_collect_ctx *ctx = data;
	struct llog_changelog_user_rec2 *rec;
	struct changelog_nl_user *user;
	char user_name[CHANGELOG_USER_NAMELEN_FULL];

	if (!(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN))
		return -EINVAL;

	rec = container_of(hdr, typeof(*rec), cur_hdr);

	if (rec->cur_hdr.lrh_type != CHANGELOG_USER_REC &&
	    rec->cur_hdr.lrh_type != CHANGELOG_USER_REC2)
		return 0;

	user = genradix_ptr_alloc(ctx->ccc_users, *ctx->ccc_nusers,
				  GFP_KERNEL);
	if (!user) {
		ctx->ccc_rc = -ENOMEM;
		return -ENOMEM;
	}

	strscpy(user->cnu_id,
		mdd_chlg_username(rec, user_name, sizeof(user_name)),
		sizeof(user->cnu_id));
	user->cnu_index = rec->cur_endrec;
	user->cnu_idle_secs = (__u32)ktime_get_real_seconds() - rec->cur_time;
	user->cnu_mask = mdd_chlg_usermask(rec);

	(*ctx->ccc_nusers)++;

	return 0;
}

static int changelog_nl_collect(changelog_entry_radix_t *entries,
				unsigned int *nentries,
				changelog_user_radix_t *users,
				unsigned int *nusers)
{
	changelog_entry_radix_t *eradix = entries;
	changelog_user_radix_t *uradix = users;
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
		struct mdd_device *mdd;
		struct changelog_nl_entry *entry;
		struct llog_ctxt *ctxt;
		struct chlg_collect_ctx cctx;

		if (!obd || obd->obd_stopping)
			continue;

		if (!test_bit(OBDF_SET_UP, obd->obd_flags))
			continue;

		if (strcmp(obd->obd_type->typ_name, LUSTRE_MDD_NAME) != 0)
			continue;

		mdd = lu2mdd_dev(obd->obd_lu_dev);
		if (!mdd)
			continue;

		entry = genradix_ptr_alloc(eradix, *nentries, GFP_KERNEL);
		if (!entry) {
			rc = -ENOMEM;
			break;
		}

		strscpy(entry->cne_source, obd->obd_name,
			sizeof(entry->cne_source));

		spin_lock(&mdd->mdd_cl.mc_lock);
		entry->cne_index = mdd->mdd_cl.mc_index;
		spin_unlock(&mdd->mdd_cl.mc_lock);

		entry->cne_user_offset = *nusers;
		entry->cne_num_users = 0;

		ctxt = llog_get_context(obd,
					LLOG_CHANGELOG_USER_ORIG_CTXT);
		if (!ctxt) {
			(*nentries)++;
			continue;
		}

		cctx.ccc_users = uradix;
		cctx.ccc_nusers = nusers;
		cctx.ccc_rc = 0;

		rc = llog_cat_process(&env, ctxt->loc_handle,
				      changelog_collect_user_cb,
				      &cctx, 0, 0);
		llog_ctxt_put(ctxt);

		if (rc < 0 || cctx.ccc_rc < 0) {
			rc = rc ? rc : cctx.ccc_rc;
			break;
		}
		rc = 0;

		entry->cne_num_users = *nusers - entry->cne_user_offset;
		(*nentries)++;
	}

	lu_env_fini(&env);
	RETURN(rc);
}

/* ---- Key lists ---- */

static struct ln_key_list changelog_list = {
	.lkl_maxattr			= LUSTRE_CHANGELOG_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_CHANGELOG_ATTR_HDR]	= {
			.lkp_value		= "changelog",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_CHANGELOG_ATTR_SOURCE]	= {
			.lkp_value		= "source",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_CHANGELOG_ATTR_INDEX]	= {
			.lkp_value		= "index",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_CHANGELOG_ATTR_USERS]	= {
			.lkp_value		= "users",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED,
		},
	},
};

static struct ln_key_list changelog_user_list = {
	.lkl_maxattr			= LUSTRE_CHANGELOG_USER_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_CHANGELOG_USER_ATTR_ID]	= {
			.lkp_value		= "id",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_CHANGELOG_USER_ATTR_INDEX] = {
			.lkp_value		= "index",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_CHANGELOG_USER_ATTR_IDLE_SECS] = {
			.lkp_value		= "idle_secs",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_CHANGELOG_USER_ATTR_MASK] = {
			.lkp_value		= "mask",
			.lkp_data_type		= NLA_U32,
		},
	},
};

/* ---- Context struct ---- */

struct genl_changelog_list {
	changelog_entry_radix_t			gcl_entries;
	changelog_user_radix_t			gcl_users;
	unsigned int				gcl_entry_count;
	unsigned int				gcl_user_count;
	unsigned int				gcl_index;
};

static inline struct genl_changelog_list *
changelog_dump_ctx(struct netlink_callback *cb)
{
	return (struct genl_changelog_list *)cb->args[0];
}

/* ---- MDD_NL_CMD_CHANGELOG handlers ---- */

static int mdd_changelog_start(struct netlink_callback *cb)
{
	struct netlink_ext_ack *extack = cb->extack;
	struct genl_changelog_list *clist;
	int rc;

	LIBCFS_ALLOC(clist, sizeof(*clist));
	if (!clist) {
		NL_SET_ERR_MSG(extack, "failed to setup changelog list");
		return -ENOMEM;
	}
	genradix_init(&clist->gcl_entries);
	genradix_init(&clist->gcl_users);
	clist->gcl_entry_count = 0;
	clist->gcl_user_count = 0;
	clist->gcl_index = 0;
	cb->args[0] = (long)clist;

	rc = changelog_nl_collect(&clist->gcl_entries,
				  &clist->gcl_entry_count,
				  &clist->gcl_users,
				  &clist->gcl_user_count);
	if (rc < 0) {
		genradix_free(&clist->gcl_users);
		genradix_free(&clist->gcl_entries);
		LIBCFS_FREE(clist, sizeof(*clist));
		cb->args[0] = 0;
		return rc;
	}

	return 0;
}

static int mdd_changelog_dump(struct sk_buff *msg,
			      struct netlink_callback *cb)
{
	struct genl_changelog_list *clist = changelog_dump_ctx(cb);
	struct netlink_ext_ack *extack = cb->extack;
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int rc = 0;

	if (!clist)
		return 0;

	if (clist->gcl_index == 0) {
		const struct ln_key_list *all[] = {
			&changelog_list, &changelog_user_list, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&mdd_family,
						NLM_F_CREATE | NLM_F_MULTI,
						MDD_NL_CMD_CHANGELOG, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack,
				       "failed to send changelog key table");
			return rc;
		}
	}

	while (clist->gcl_index < clist->gcl_entry_count) {
		struct changelog_nl_entry *entry;
		void *hdr;
		unsigned int u;

		entry = genradix_ptr(&clist->gcl_entries, clist->gcl_index);
		if (!entry) {
			clist->gcl_index++;
			continue;
		}

		hdr = genlmsg_put(msg, portid, seq, &mdd_family,
				  NLM_F_MULTI, MDD_NL_CMD_CHANGELOG);
		if (!hdr) {
			rc = -EMSGSIZE;
			break;
		}

		if (clist->gcl_index == 0)
			rc = nla_put_string(msg,
					    LUSTRE_CHANGELOG_ATTR_HDR,
					    "");
		if (rc < 0 ||
		    nla_put_string(msg, LUSTRE_CHANGELOG_ATTR_SOURCE,
				   entry->cne_source) ||
		    nla_put_u64_64bit(msg, LUSTRE_CHANGELOG_ATTR_INDEX,
				      entry->cne_index,
				      LUSTRE_CHANGELOG_ATTR_PAD)) {
			genlmsg_cancel(msg, hdr);
			rc = -EMSGSIZE;
			break;
		}

		for (u = 0; u < entry->cne_num_users; u++) {
			struct changelog_nl_user *user;
			struct nlattr *user_nest;
			struct nlattr *user_inner;

			user = genradix_ptr(&clist->gcl_users,
					    entry->cne_user_offset + u);
			if (!user)
				continue;

			user_nest = nla_nest_start(msg,
				LUSTRE_CHANGELOG_ATTR_USERS + u);
			if (!user_nest) {
				rc = -EMSGSIZE;
				break;
			}

			user_inner = nla_nest_start(msg, 0);
			if (!user_inner) {
				nla_nest_cancel(msg, user_nest);
				rc = -EMSGSIZE;
				break;
			}

			if (nla_put_string(msg,
				LUSTRE_CHANGELOG_USER_ATTR_ID,
				user->cnu_id) ||
			    nla_put_u64_64bit(msg,
				LUSTRE_CHANGELOG_USER_ATTR_INDEX,
				user->cnu_index,
				LUSTRE_CHANGELOG_USER_ATTR_PAD) ||
			    nla_put_u32(msg,
				LUSTRE_CHANGELOG_USER_ATTR_IDLE_SECS,
				user->cnu_idle_secs) ||
			    nla_put_u32(msg,
				LUSTRE_CHANGELOG_USER_ATTR_MASK,
				user->cnu_mask)) {
				nla_nest_cancel(msg, user_inner);
				nla_nest_cancel(msg, user_nest);
				rc = -EMSGSIZE;
				break;
			}

			nla_nest_end(msg, user_inner);
			nla_nest_end(msg, user_nest);
		}

		if (rc) {
			genlmsg_cancel(msg, hdr);
			break;
		}

		genlmsg_end(msg, hdr);
		clist->gcl_index++;
	}

	return rc;
}

static int mdd_changelog_done(struct netlink_callback *cb)
{
	struct genl_changelog_list *clist = changelog_dump_ctx(cb);

	if (clist) {
		genradix_free(&clist->gcl_users);
		genradix_free(&clist->gcl_entries);
		LIBCFS_FREE(clist, sizeof(*clist));
		cb->args[0] = 0;
	}

	return 0;
}

/* ---- "mdd" genetlink family ---- */

static const struct genl_multicast_group mdd_mcast_grps[] = {
	{ .name = "changelog" },
};

static const struct genl_ops mdd_genl_ops[] = {
	{
		.cmd	= MDD_NL_CMD_CHANGELOG,
		.start	= mdd_changelog_start,
		.dumpit	= mdd_changelog_dump,
		.done	= mdd_changelog_done,
	},
};

static struct genl_family mdd_family = {
	.name		= MDD_GENL_NAME,
	.version	= MDD_GENL_VERSION,
	.module		= THIS_MODULE,
	.ops		= mdd_genl_ops,
	.n_ops		= ARRAY_SIZE(mdd_genl_ops),
	.mcgrps		= mdd_mcast_grps,
	.n_mcgrps	= ARRAY_SIZE(mdd_mcast_grps),
#ifdef GENL_FAMILY_HAS_RESV_START_OP
	.resv_start_op	= __MDD_NL_CMD_MAX_PLUS_ONE,
#endif
};

int mdd_netlink_init(void)
{
	return genl_register_family(&mdd_family);
}

void mdd_netlink_fini(void)
{
	genl_unregister_family(&mdd_family);
}
