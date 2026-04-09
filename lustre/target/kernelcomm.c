// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Server-only netlink handlers extracted from kernelcomm.c.
 * This file is only compiled in server builds (HAVE_SERVER_SUPPORT).
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/file.h>
#include <linux/types.h>
#include <linux/generic-radix-tree.h>
#include <linux/glob.h>
#include <lustre_compat/net/linux-net.h>
#include <lnet/lib-lnet.h>
#include <lustre_dlm.h>
#include <lustre_kernelcomm.h>
#include <lustre_nodemap.h>
#include <obd_class.h>
#include <obd_support.h>
#include <uapi/linux/lustre/lustre_disk.h>


static bool obd_is_server_type(const char *type_name)
{
	return strcmp(type_name, LUSTRE_MDT_NAME) == 0 ||
	       strcmp(type_name, LUSTRE_OST_NAME) == 0;
}

static bool obd_is_server_type_match(struct obd_device *obd)
{
	return obd_is_server_type(obd->obd_type->typ_name);
}

/* Forward declaration for target family (defined at bottom of file) */
static struct genl_family target_family;

/* TARGET_CMD_RECOVERY handlers */

static struct ln_key_list recovery_list = {
	.lkl_maxattr			= LUSTRE_RECOVERY_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_RECOVERY_ATTR_HDR]	= {
			.lkp_value		= "recovery_status",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_RECOVERY_ATTR_SOURCE]	= {
			.lkp_value		= "source",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_RECOVERY_ATTR_STATUS]	= {
			.lkp_value		= "status",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_RECOVERY_ATTR_DURATION]	= {
			.lkp_value		= "recovery_duration",
			.lkp_data_type		= NLA_S64,
		},
		[LUSTRE_RECOVERY_ATTR_TIME_REMAINING] = {
			.lkp_value		= "time_remaining",
			.lkp_data_type		= NLA_S64,
		},
		[LUSTRE_RECOVERY_ATTR_CONNECTED_CLIENTS] = {
			.lkp_value		= "connected_clients",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_RECOVERY_ATTR_COMPLETED_CLIENTS] = {
			.lkp_value		= "completed_clients",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_RECOVERY_ATTR_EVICTED_CLIENTS] = {
			.lkp_value		= "evicted_clients",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_RECOVERY_ATTR_MAX_CLIENTS] = {
			.lkp_value		= "max_clients",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_RECOVERY_ATTR_REPLAYED_REQUESTS] = {
			.lkp_value		= "replayed_requests",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_RECOVERY_ATTR_QUEUED_REQUESTS] = {
			.lkp_value		= "queued_requests",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_RECOVERY_ATTR_NEXT_TRANSNO] = {
			.lkp_value		= "next_transno",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_RECOVERY_ATTR_VBR]	= {
			.lkp_value		= "vbr",
			.lkp_data_type		= NLA_U8,
		},
		[LUSTRE_RECOVERY_ATTR_IR]	= {
			.lkp_value		= "ir",
			.lkp_data_type		= NLA_U8,
		},
	},
};

struct recovery_entry {
	char			re_source[MAX_OBD_NAME];
	struct obd_device	*re_obd;
};

struct recovery_ctx {
	struct lustre_nl_ctx		base;
	GENRADIX(struct recovery_entry)	list;
};

static int recovery_collect(struct lustre_nl_ctx *base, struct obd_device *obd)
{
	struct recovery_ctx *ctx = container_of(base, struct recovery_ctx,
						base);
	struct recovery_entry *entry;

	entry = genradix_ptr_alloc(&ctx->list, ctx->base.count++,
				   GFP_ATOMIC);
	if (!entry) {
		ctx->base.count--;
		return -ENOMEM;
	}

	strscpy(entry->re_source, obd->obd_name,
		sizeof(entry->re_source));
	entry->re_obd = obd;
	class_incref(obd, "netlink_recovery", current);
	return 0;
}

static void recovery_release(void *ventry)
{
	struct recovery_entry *entry = ventry;

	if (entry->re_obd)
		class_decref(entry->re_obd, "netlink_recovery", current);
}

static int recovery_dump_one(struct sk_buff *msg, void *ventry,
			     bool first)
{
	struct recovery_entry *entry = ventry;
	struct obd_device *obd = entry->re_obd;
	const char *status;

	if (first) {
		int rc = nla_put_string(msg,
					LUSTRE_RECOVERY_ATTR_HDR, "");
		if (rc)
			return rc;
	}

	if (nla_put_string(msg, LUSTRE_RECOVERY_ATTR_SOURCE,
			   entry->re_source))
		return -EMSGSIZE;

	if (obd->obd_stopping) {
		status = "INACTIVE";
	} else if (!obd->obd_recovery_end &&
		   !obd->obd_recovery_start) {
		status = "INACTIVE";
	} else if (obd->obd_recovery_end > 0) {
		status = "COMPLETE";
	} else if (test_bit(OBDF_RECOVERING, obd->obd_flags)) {
		status = "RECOVERING";
	} else {
		status = "WAITING";
	}

	if (nla_put_string(msg, LUSTRE_RECOVERY_ATTR_STATUS, status) ||
	    nla_put_u32(msg, LUSTRE_RECOVERY_ATTR_MAX_CLIENTS,
			atomic_read(&obd->obd_max_recoverable_clients)) ||
	    nla_put_u8(msg, LUSTRE_RECOVERY_ATTR_VBR,
		       test_bit(OBDF_VERSION_RECOV, obd->obd_flags) ? 1 : 0) ||
	    nla_put_u8(msg, LUSTRE_RECOVERY_ATTR_IR,
		       obd->obd_no_ir ? 0 : 1))
		return -EMSGSIZE;

	if (strcmp(status, "COMPLETE") == 0) {
		if (nla_put_s64(msg, LUSTRE_RECOVERY_ATTR_DURATION,
				obd->obd_recovery_end - obd->obd_recovery_start,
				LUSTRE_RECOVERY_ATTR_PAD) ||
		    nla_put_u32(msg, LUSTRE_RECOVERY_ATTR_COMPLETED_CLIENTS,
				atomic_read(&obd->obd_max_recoverable_clients) -
				obd->obd_stale_clients) ||
		    nla_put_u32(msg, LUSTRE_RECOVERY_ATTR_REPLAYED_REQUESTS,
				obd->obd_replayed_requests))
			return -EMSGSIZE;
	}

	if (strcmp(status, "RECOVERING") == 0) {
		s64 remaining = (s64)(obd->obd_recovery_start +
				      obd->obd_recovery_timeout) -
				ktime_get_seconds();

		if (remaining < 0)
			remaining = 0;

		if (nla_put_s64(msg, LUSTRE_RECOVERY_ATTR_TIME_REMAINING,
				remaining, LUSTRE_RECOVERY_ATTR_PAD) ||
		    nla_put_u32(msg, LUSTRE_RECOVERY_ATTR_CONNECTED_CLIENTS,
				atomic_read(&obd->obd_connected_clients)) ||
		    nla_put_u32(msg, LUSTRE_RECOVERY_ATTR_COMPLETED_CLIENTS,
				atomic_read(&obd->obd_lock_replay_clients)) ||
		    nla_put_u32(msg, LUSTRE_RECOVERY_ATTR_EVICTED_CLIENTS,
				obd->obd_stale_clients) ||
		    nla_put_u32(msg, LUSTRE_RECOVERY_ATTR_REPLAYED_REQUESTS,
				obd->obd_replayed_requests) ||
		    nla_put_u32(msg, LUSTRE_RECOVERY_ATTR_QUEUED_REQUESTS,
				obd->obd_requests_queued_for_recovery) ||
		    nla_put_u64_64bit(msg, LUSTRE_RECOVERY_ATTR_NEXT_TRANSNO,
				      obd->obd_next_recovery_transno,
				      LUSTRE_RECOVERY_ATTR_PAD))
			return -EMSGSIZE;
	}

	return 0;
}

static const struct ln_key_list *recovery_keys[] = {
	&recovery_list, NULL
};

static const struct lustre_nl_obd_ops recovery_ops = {
	.refname	= "netlink_recovery",
	.filter_key	= "source",
	.family		= &target_family,
	.entry_size	= sizeof(struct recovery_entry),
	.ctx_size	= sizeof(struct recovery_ctx),
	.list_offset	= offsetof(struct recovery_ctx, list),
	.cmd		= TARGET_CMD_RECOVERY,
	.keys		= recovery_keys,
	.device_match	= obd_is_server_type_match,
	.collect	= recovery_collect,
	.release	= recovery_release,
	.dump_one	= recovery_dump_one,
};

static int lustre_recovery_start(struct netlink_callback *cb)
{
	return lustre_obd_nl_start(cb, &recovery_ops);
}

static int lustre_recovery_dump(struct sk_buff *msg,
				struct netlink_callback *cb)
{
	return lustre_obd_nl_dump(msg, cb);
}

static int lustre_recovery_done(struct netlink_callback *cb)
{
	return lustre_obd_nl_done(cb);
}

/* TARGET_CMD_OBD_PARAMS handlers */

static struct ln_key_list obd_params_list = {
	.lkl_maxattr			= LUSTRE_OBD_PARAMS_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_OBD_PARAMS_ATTR_HDR]	= {
			.lkp_value		= "obd_params",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_OBD_PARAMS_ATTR_SOURCE]	= {
			.lkp_value		= "source",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_OBD_PARAMS_ATTR_CLASS]	= {
			.lkp_value		= "class",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_OBD_PARAMS_ATTR_KBYTES_TOTAL] = {
			.lkp_value		= "kbytestotal",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_OBD_PARAMS_ATTR_KBYTES_FREE] = {
			.lkp_value		= "kbytesfree",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_OBD_PARAMS_ATTR_KBYTES_AVAIL] = {
			.lkp_value		= "kbytesavail",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_OBD_PARAMS_ATTR_FILES_TOTAL] = {
			.lkp_value		= "filestotal",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_OBD_PARAMS_ATTR_FILES_FREE] = {
			.lkp_value		= "filesfree",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_OBD_PARAMS_ATTR_NUM_EXPORTS] = {
			.lkp_value		= "num_exports",
			.lkp_data_type		= NLA_U32,
		},
		[LUSTRE_OBD_PARAMS_ATTR_TOT_DIRTY] = {
			.lkp_value		= "tot_dirty",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_OBD_PARAMS_ATTR_TOT_GRANTED] = {
			.lkp_value		= "tot_granted",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_OBD_PARAMS_ATTR_TOT_PENDING] = {
			.lkp_value		= "tot_pending",
			.lkp_data_type		= NLA_U64,
		},
	},
};

struct obd_params_entry {
	char			ope_source[MAX_OBD_NAME];
	char			ope_class[16];
	struct obd_device	*ope_obd;
};

static u64 obd_statfs_to_kb(u64 blocks, u32 bsize)
{
	if (bsize < 1024)
		return blocks * bsize / 1024;

	return blocks * (bsize / 1024);
}

struct obd_params_ctx {
	struct lustre_nl_ctx			base;
	GENRADIX(struct obd_params_entry)	list;
};

static int obd_params_collect(struct lustre_nl_ctx *base,
			      struct obd_device *obd)
{
	struct obd_params_ctx *ctx = container_of(base, struct obd_params_ctx,
						  base);
	struct obd_params_entry *entry;

	entry = genradix_ptr_alloc(&ctx->list, ctx->base.count++,
				   GFP_ATOMIC);
	if (!entry) {
		ctx->base.count--;
		return -ENOMEM;
	}

	strscpy(entry->ope_source, obd->obd_name,
		sizeof(entry->ope_source));
	strscpy(entry->ope_class, obd->obd_type->typ_name,
		sizeof(entry->ope_class));
	entry->ope_obd = obd;
	class_incref(obd, "netlink_obd_params", current);
	return 0;
}

static void obd_params_release(void *ventry)
{
	struct obd_params_entry *entry = ventry;

	if (entry->ope_obd)
		class_decref(entry->ope_obd, "netlink_obd_params", current);
}

static int obd_params_dump_one(struct sk_buff *msg, void *ventry,
			       bool first)
{
	struct obd_params_entry *entry = ventry;
	struct tg_grants_data *tgd;
	struct obd_statfs osfs;
	struct lu_target *lut;
	int rc;

	if (first) {
		rc = nla_put_string(msg, LUSTRE_OBD_PARAMS_ATTR_HDR, "");
		if (rc)
			return rc;
	}

	if (nla_put_string(msg, LUSTRE_OBD_PARAMS_ATTR_SOURCE,
			   entry->ope_source) ||
	    nla_put_string(msg, LUSTRE_OBD_PARAMS_ATTR_CLASS,
			   entry->ope_class))
		return -EMSGSIZE;

	lut = obd2obt(entry->ope_obd)->obt_lut;
	tgd = &lut->lut_tgd;

	memset(&osfs, 0, sizeof(osfs));
	rc = dt_statfs(NULL, lut->lut_bottom, &osfs);
	if (rc)
		return rc;

	if (nla_put_u64_64bit(msg, LUSTRE_OBD_PARAMS_ATTR_KBYTES_TOTAL,
			      obd_statfs_to_kb(osfs.os_blocks, osfs.os_bsize),
			      LUSTRE_OBD_PARAMS_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, LUSTRE_OBD_PARAMS_ATTR_KBYTES_FREE,
			      obd_statfs_to_kb(osfs.os_bfree, osfs.os_bsize),
			      LUSTRE_OBD_PARAMS_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, LUSTRE_OBD_PARAMS_ATTR_KBYTES_AVAIL,
			      obd_statfs_to_kb(osfs.os_bavail, osfs.os_bsize),
			      LUSTRE_OBD_PARAMS_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, LUSTRE_OBD_PARAMS_ATTR_FILES_TOTAL,
			      osfs.os_files,
			      LUSTRE_OBD_PARAMS_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, LUSTRE_OBD_PARAMS_ATTR_FILES_FREE,
			      osfs.os_ffree,
			      LUSTRE_OBD_PARAMS_ATTR_PAD) ||
	    nla_put_u32(msg, LUSTRE_OBD_PARAMS_ATTR_NUM_EXPORTS,
			entry->ope_obd->obd_num_exports) ||
	    nla_put_u64_64bit(msg, LUSTRE_OBD_PARAMS_ATTR_TOT_DIRTY,
			      tgd->tgd_tot_dirty,
			      LUSTRE_OBD_PARAMS_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, LUSTRE_OBD_PARAMS_ATTR_TOT_GRANTED,
			      tgd->tgd_tot_granted,
			      LUSTRE_OBD_PARAMS_ATTR_PAD) ||
	    nla_put_u64_64bit(msg, LUSTRE_OBD_PARAMS_ATTR_TOT_PENDING,
			      tgd->tgd_tot_pending,
			      LUSTRE_OBD_PARAMS_ATTR_PAD))
		return -EMSGSIZE;

	return 0;
}

static const struct ln_key_list *obd_params_keys[] = {
	&obd_params_list, NULL
};

static const struct lustre_nl_obd_ops obd_params_ops = {
	.refname	= "netlink_obd_params",
	.filter_key	= "source",
	.family		= &target_family,
	.entry_size	= sizeof(struct obd_params_entry),
	.ctx_size	= sizeof(struct obd_params_ctx),
	.list_offset	= offsetof(struct obd_params_ctx, list),
	.cmd		= TARGET_CMD_OBD_PARAMS,
	.keys		= obd_params_keys,
	.device_match	= obd_is_server_type_match,
	.collect	= obd_params_collect,
	.release	= obd_params_release,
	.dump_one	= obd_params_dump_one,
};

int lustre_obd_params_start(struct netlink_callback *cb)
{
	return lustre_obd_nl_start(cb, &obd_params_ops);
}

int lustre_obd_params_dump(struct sk_buff *msg, struct netlink_callback *cb)
{
	return lustre_obd_nl_dump(msg, cb);
}

int lustre_obd_params_done(struct netlink_callback *cb)
{
	return lustre_obd_nl_done(cb);
}

/* TARGET_CMD_BRW_STATS handlers */

static struct ln_key_list brw_stats_list = {
	.lkl_maxattr			= LUSTRE_BRW_STATS_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_BRW_STATS_ATTR_HDR]	= {
			.lkp_value		= "brw_stats",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_BRW_STATS_ATTR_SOURCE]	= {
			.lkp_value		= "source",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_BRW_STATS_ATTR_TIMESTAMP] = {
			.lkp_value		= "snapshot_time",
			.lkp_data_type		= NLA_S64,
		},
		[LUSTRE_BRW_STATS_ATTR_HISTOGRAM] = {
			.lkp_value		= "histogram",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED,
		},
	},
};

static struct ln_key_list brw_hist_list = {
	.lkl_maxattr			= LUSTRE_BRW_HIST_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_BRW_HIST_ATTR_NAME]	= {
			.lkp_value		= "name",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_BRW_HIST_ATTR_UNITS]	= {
			.lkp_value		= "units",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_BRW_HIST_ATTR_READ]	= {
			.lkp_value		= "read",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_BRW_HIST_ATTR_WRITE]	= {
			.lkp_value		= "write",
			.lkp_data_type		= NLA_U64,
		},
	},
};

struct brw_stats_entry {
	char			bse_source[MAX_OBD_NAME];
	struct obd_device	*bse_obd;
	struct brw_stats	*bse_stats;
};

struct brw_stats_ctx {
	struct lustre_nl_ctx			base;
	GENRADIX(struct brw_stats_entry)	list;
};

static int brw_stats_collect(struct lustre_nl_ctx *base,
			     struct obd_device *obd)
{
	struct brw_stats_ctx *ctx = container_of(base, struct brw_stats_ctx,
						base);
	struct brw_stats_entry *entry;
	struct brw_stats *bs;

	bs = obd2obt(obd)->obt_lut->lut_bottom->dd_brw_stats;
	if (!bs)
		return 0;

	entry = genradix_ptr_alloc(&ctx->list, ctx->base.count++,
				   GFP_ATOMIC);
	if (!entry) {
		ctx->base.count--;
		return -ENOMEM;
	}

	strscpy(entry->bse_source, obd->obd_name,
		sizeof(entry->bse_source));
	entry->bse_obd = obd;
	entry->bse_stats = bs;
	class_incref(obd, "netlink_brw_stats", current);
	return 0;
}

static void brw_stats_release(void *ventry)
{
	struct brw_stats_entry *entry = ventry;

	if (entry->bse_obd)
		class_decref(entry->bse_obd, "netlink_brw_stats", current);
}

static int brw_stats_dump_one(struct sk_buff *msg, void *ventry,
			      bool first)
{
	struct brw_stats_entry *entry = ventry;
	struct brw_stats *bs = entry->bse_stats;
	int i;

	if (first) {
		int rc = nla_put_string(msg,
					LUSTRE_BRW_STATS_ATTR_HDR, "");
		if (rc)
			return rc;
	}

	if (nla_put_string(msg, LUSTRE_BRW_STATS_ATTR_SOURCE,
			   entry->bse_source) ||
	    nla_put_s64(msg, LUSTRE_BRW_STATS_ATTR_TIMESTAMP,
			ktime_to_ns(bs->bs_init),
			LUSTRE_BRW_STATS_ATTR_PAD))
		return -EMSGSIZE;

	for (i = 0; i < ARRAY_SIZE(bs->bs_props); i++) {
		struct nlattr *hist_nest, *hist_inner, *bucket_nest;
		int j;

		if (!bs->bs_props[i].bsp_name)
			continue;

		hist_nest = nla_nest_start(msg,
				LUSTRE_BRW_STATS_ATTR_HISTOGRAM);
		if (!hist_nest)
			return -EMSGSIZE;

		hist_inner = nla_nest_start(msg, 0);
		if (!hist_inner) {
			nla_nest_cancel(msg, hist_nest);
			return -EMSGSIZE;
		}

		if (nla_put_string(msg, LUSTRE_BRW_HIST_ATTR_NAME,
				   bs->bs_props[i].bsp_name) ||
		    nla_put_string(msg, LUSTRE_BRW_HIST_ATTR_UNITS,
				   bs->bs_props[i].bsp_units)) {
			nla_nest_cancel(msg, hist_inner);
			nla_nest_cancel(msg, hist_nest);
			return -EMSGSIZE;
		}

		/* Read buckets */
		bucket_nest = nla_nest_start(msg,
				LUSTRE_BRW_HIST_ATTR_READ);
		if (!bucket_nest) {
			nla_nest_cancel(msg, hist_inner);
			nla_nest_cancel(msg, hist_nest);
			return -EMSGSIZE;
		}
		for (j = 0; j < OBD_HIST_MAX; j++) {
			if (nla_put_u64_64bit(msg, j + 1,
				lprocfs_oh_counter_pcpu(
					&bs->bs_hist[i * 2], j),
				LUSTRE_BRW_HIST_ATTR_PAD)) {
				nla_nest_cancel(msg, bucket_nest);
				nla_nest_cancel(msg, hist_inner);
				nla_nest_cancel(msg, hist_nest);
				return -EMSGSIZE;
			}
		}
		nla_nest_end(msg, bucket_nest);

		/* Write buckets */
		bucket_nest = nla_nest_start(msg,
				LUSTRE_BRW_HIST_ATTR_WRITE);
		if (!bucket_nest) {
			nla_nest_cancel(msg, hist_inner);
			nla_nest_cancel(msg, hist_nest);
			return -EMSGSIZE;
		}
		for (j = 0; j < OBD_HIST_MAX; j++) {
			if (nla_put_u64_64bit(msg, j + 1,
				lprocfs_oh_counter_pcpu(
					&bs->bs_hist[i * 2 + 1], j),
				LUSTRE_BRW_HIST_ATTR_PAD)) {
				nla_nest_cancel(msg, bucket_nest);
				nla_nest_cancel(msg, hist_inner);
				nla_nest_cancel(msg, hist_nest);
				return -EMSGSIZE;
			}
		}
		nla_nest_end(msg, bucket_nest);

		nla_nest_end(msg, hist_inner);
		nla_nest_end(msg, hist_nest);
	}

	return 0;
}

static const struct ln_key_list *brw_stats_keys[] = {
	&brw_stats_list, &brw_hist_list, NULL
};

static const struct lustre_nl_obd_ops brw_stats_ops = {
	.refname	= "netlink_brw_stats",
	.filter_key	= "source",
	.family		= &target_family,
	.entry_size	= sizeof(struct brw_stats_entry),
	.ctx_size	= sizeof(struct brw_stats_ctx),
	.list_offset	= offsetof(struct brw_stats_ctx, list),
	.min_alloc	= 32768,
	.cmd		= TARGET_CMD_BRW_STATS,
	.keys		= brw_stats_keys,
	.device_match	= obd_is_server_type_match,
	.collect	= brw_stats_collect,
	.release	= brw_stats_release,
	.dump_one	= brw_stats_dump_one,
};

static int lustre_brw_stats_start(struct netlink_callback *cb)
{
	return lustre_obd_nl_start(cb, &brw_stats_ops);
}

static int lustre_brw_stats_dump(struct sk_buff *msg,
				 struct netlink_callback *cb)
{
	return lustre_obd_nl_dump(msg, cb);
}

static int lustre_brw_stats_done(struct netlink_callback *cb)
{
	return lustre_obd_nl_done(cb);
}
/*
 * Dataset key list shared by EXPORTS and JOB_STATS handlers.
 * Must be defined before both sections.
 */
static struct ln_key_list job_stats_dataset_list = {
	.lkl_maxattr			= LUSTRE_STATS_ATTR_DATASET_MAX,
	.lkl_list			= {
		[LUSTRE_STATS_ATTR_DATASET_NAME] = {
			.lkp_value		= "name",
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_STATS_ATTR_DATASET_COUNT] = {
			.lkp_value		= "count",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_STATS_ATTR_DATASET_UNITS] = {
			.lkp_value		= "units",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_STATS_ATTR_DATASET_MINIMUM] = {
			.lkp_value		= "minimum",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_STATS_ATTR_DATASET_MAXIMUM] = {
			.lkp_value		= "maximum",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_STATS_ATTR_DATASET_SUM] = {
			.lkp_value		= "sum",
			.lkp_data_type		= NLA_U64,
		},
		[LUSTRE_STATS_ATTR_DATASET_SUMSQUARE] = {
			.lkp_value		= "sumsquare",
			.lkp_data_type		= NLA_U64,
		},
	},
};

/* TARGET_CMD_EXPORTS handlers */

static struct ln_key_list export_list = {
	.lkl_maxattr			= LUSTRE_EXPORT_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_EXPORT_ATTR_HDR]	= {
			.lkp_value		= "exports",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_EXPORT_ATTR_SOURCE]	= {
			.lkp_value		= "source",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_EXPORT_ATTR_NID]	= {
			.lkp_value		= "nid",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_EXPORT_ATTR_NODEMAP]	= {
			.lkp_value		= "nodemap",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_EXPORT_ATTR_DATASET]	= {
			.lkp_value		= "dataset",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED,
		},
	},
};

struct export_entry {
	char			ee_source[MAX_OBD_NAME];
	char			ee_nid[LNET_NIDSTR_SIZE];
	char			ee_nodemap[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	struct nid_stat		*ee_nidstat;
	struct obd_device	*ee_obd;
};

struct genl_export_list {
	unsigned int				gel_index;
	unsigned int				gel_count;
	GENRADIX(struct export_entry)		gel_list;
};

static inline struct genl_export_list *
export_dump_ctx(struct netlink_callback *cb)
{
	return (struct genl_export_list *)cb->args[0];
}

int lustre_export_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
	struct netlink_ext_ack *extack = cb->extack;
	int msg_len = genlmsg_len(gnlh);
	struct genl_export_list *elist;
	struct obd_device *obd = NULL;
	char filter[MAX_OBD_NAME * 3];
	unsigned long idx = 0;
	bool have_filter = false;
	int rc = 0;

	LIBCFS_ALLOC(elist, sizeof(*elist));
	if (!elist) {
		NL_SET_ERR_MSG(extack, "failed to setup export list");
		return -ENOMEM;
	}
	genradix_init(&elist->gel_list);
	elist->gel_index = 0;
	elist->gel_count = 0;
	cb->args[0] = (long)elist;

	memset(filter, 0, sizeof(filter));
	if (msg_len > 0) {
		struct nlattr *params = genlmsg_data(gnlh);
		struct nlattr *dev;
		int rem;

		if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
			NL_SET_ERR_MSG(extack, "no configuration");
			GOTO(report_err, rc = -EINVAL);
		}

		nla_for_each_nested(dev, params, rem) {
			struct nlattr *prop;
			int rem2;

			nla_for_each_nested(prop, dev, rem2) {
				if (nla_type(prop) != LN_SCALAR_ATTR_VALUE ||
				    nla_strcmp(prop, "source") != 0)
					continue;

				prop = nla_next(prop, &rem2);
				if (!nla_ok(prop, rem2) ||
				    nla_type(prop) != LN_SCALAR_ATTR_VALUE)
					GOTO(report_err, rc = -EINVAL);

				rc = nla_strscpy(filter, prop,
						 sizeof(filter));
				if (rc < 0)
					GOTO(report_err, rc);
				rc = 0;
				have_filter = true;
			}
		}
	}

	obd_device_lock();
	obd_device_for_each(idx, obd) {
		unsigned int count_before;
		struct nid_stat *ns;

		if (!obd_is_server_type(obd->obd_type->typ_name))
			continue;

		if (!test_bit(OBDF_SET_UP, obd->obd_flags))
			continue;

		/* Skip devices in recovery — export data structures
		 * are in flux and nid_stat entries may be freed by
		 * lprocfs_free_per_client_stats() while we hold refs,
		 * leading to use-after-free in lustre_export_dump().
		 */
		if (test_bit(OBDF_RECOVERING, obd->obd_flags))
			continue;

		if (have_filter &&
		    !glob_match(filter, obd->obd_name))
			continue;

		count_before = elist->gel_count;

		spin_lock(&obd->obd_nid_lock);
		list_for_each_entry(ns, &obd->obd_nid_stats, nid_list) {
			struct export_entry *entry;

			if (!ns->nid_stats)
				continue;

			entry = genradix_ptr_alloc(&elist->gel_list,
						   elist->gel_count++,
						   GFP_ATOMIC);
			if (!entry) {
				spin_unlock(&obd->obd_nid_lock);
				obd_device_unlock();
				NL_SET_ERR_MSG(extack,
					"failed to allocate export entry");
				GOTO(report_err, rc = -ENOMEM);
			}

			strscpy(entry->ee_source, obd->obd_name,
				sizeof(entry->ee_source));
			libcfs_nidstr_r(&ns->nid, entry->ee_nid,
					sizeof(entry->ee_nid));
			entry->ee_nodemap[0] = '\0';
			nidstat_getref(ns);
			entry->ee_nidstat = ns;
		}
		spin_unlock(&obd->obd_nid_lock);

		/* Take one OBD ref per entry added under the spinlock.
		 * class_incref and nodemap_test_nid may sleep,
		 * so they cannot be called while holding obd_nid_lock.
		 */
		for (; count_before < elist->gel_count; count_before++) {
			struct export_entry *entry;
			struct lnet_nid nid;

			entry = genradix_ptr(&elist->gel_list,
					     count_before);
			if (!entry)
				continue;

			class_incref(obd, "netlink_exports", current);
			entry->ee_obd = obd;

			libcfs_strnid(&nid, entry->ee_nid);
			nodemap_test_nid(&nid, entry->ee_nodemap,
					 sizeof(entry->ee_nodemap));
		}
	}
	obd_device_unlock();

	if (!elist->gel_count && have_filter)
		rc = -ENOENT;
report_err:
	if (rc < 0) {
		unsigned int i;

		for (i = 0; i < elist->gel_count; i++) {
			struct export_entry *entry;

			entry = genradix_ptr(&elist->gel_list, i);
			if (!entry)
				continue;
			if (entry->ee_nidstat)
				nidstat_putref(entry->ee_nidstat);
			if (entry->ee_obd)
				class_decref(entry->ee_obd,
					     "netlink_exports", current);
		}
		genradix_free(&elist->gel_list);
		LIBCFS_FREE(elist, sizeof(*elist));
		cb->args[0] = 0;
	}

	return rc;
}

int lustre_export_dump(struct sk_buff *msg,
		       struct netlink_callback *cb)
{
	struct genl_export_list *elist = export_dump_ctx(cb);
	struct netlink_ext_ack *extack = cb->extack;
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int idx = elist->gel_index;
	int rc = 0;

	if (!idx) {
		const struct ln_key_list *all[] = {
			&export_list, &job_stats_dataset_list, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&target_family,
						NLM_F_CREATE | NLM_F_MULTI,
						TARGET_CMD_EXPORTS, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			GOTO(send_err, rc);
		}
	}

	while (idx < elist->gel_count) {
		struct export_entry *entry;
		struct lprocfs_stats *s;
		void *hdr;

		entry = genradix_ptr(&elist->gel_list, idx++);
		if (!entry || !entry->ee_nidstat)
			continue;

		s = entry->ee_nidstat->nid_stats;
		if (!s)
			continue;

		hdr = genlmsg_put(msg, portid, seq, &target_family,
				  NLM_F_MULTI, TARGET_CMD_EXPORTS);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			idx--;
			rc = -EMSGSIZE;
			break;
		}

		if (idx == 1)
			rc = nla_put_string(msg,
					    LUSTRE_EXPORT_ATTR_HDR,
					    "");
		if (rc < 0 ||
		    nla_put_string(msg, LUSTRE_EXPORT_ATTR_SOURCE,
				   entry->ee_source) ||
		    nla_put_string(msg, LUSTRE_EXPORT_ATTR_NID,
				   entry->ee_nid) ||
		    nla_put_string(msg, LUSTRE_EXPORT_ATTR_NODEMAP,
				   entry->ee_nodemap)) {
			genlmsg_cancel(msg, hdr);
			idx--;
			rc = -EMSGSIZE;
			break;
		}

		rc = lustre_nl_put_dataset(msg, s,
					  LUSTRE_EXPORT_ATTR_DATASET);

		if (rc) {
			genlmsg_cancel(msg, hdr);
			idx--;
			break;
		}

		genlmsg_end(msg, hdr);
	}

	elist->gel_index = idx;
send_err:
	return rc;
}


int lustre_export_done(struct netlink_callback *cb)
{
	struct genl_export_list *elist;

	elist = export_dump_ctx(cb);
	if (elist) {
		unsigned int i;

		for (i = 0; i < elist->gel_count; i++) {
			struct export_entry *entry;

			entry = genradix_ptr(&elist->gel_list, i);
			if (!entry)
				continue;
			if (entry->ee_nidstat)
				nidstat_putref(entry->ee_nidstat);
			if (entry->ee_obd)
				class_decref(entry->ee_obd,
					     "netlink_exports", current);
		}
		genradix_free(&elist->gel_list);
		LIBCFS_FREE(elist, sizeof(*elist));
		cb->args[0] = 0;
	}

	return 0;
}

/* TARGET_CMD_JOB_STATS handlers */

static struct ln_key_list job_stats_list = {
	.lkl_maxattr			= LUSTRE_JOB_STATS_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_JOB_STATS_ATTR_HDR]	= {
			.lkp_value		= "job_stats",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_JOB_STATS_ATTR_SOURCE]	= {
			.lkp_value		= "source",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_JOB_STATS_ATTR_JOBID]	= {
			.lkp_value		= "job_id",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_JOB_STATS_ATTR_SNAPSHOT_TIME] = {
			.lkp_value		= "snapshot_time",
			.lkp_data_type		= NLA_S64,
		},
		[LUSTRE_JOB_STATS_ATTR_START_TIME] = {
			.lkp_value		= "start_time",
			.lkp_data_type		= NLA_S64,
		},
		[LUSTRE_JOB_STATS_ATTR_ELAPSED_TIME] = {
			.lkp_value		= "elapsed_time",
			.lkp_data_type		= NLA_S64,
		},
		[LUSTRE_JOB_STATS_ATTR_DATASET] = {
			.lkp_value		= "dataset",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED,
		},
	},
};

struct job_stats_dev_entry {
	char			jsde_source[MAX_OBD_NAME];
	struct obd_device	*jsde_obd;
	struct obd_job_stats	*jsde_stats;
};

struct job_stats_ctx {
	struct lustre_nl_ctx			base;
	u64					job_pos;
	bool					hdr_sent;
	GENRADIX(struct job_stats_dev_entry)	list;
};

static int job_stats_collect(struct lustre_nl_ctx *base,
			     struct obd_device *obd)
{
	struct job_stats_ctx *ctx = container_of(base, struct job_stats_ctx,
						base);
	struct job_stats_dev_entry *entry;

	if (!obd2obt(obd)->obt_jobstats.ojs_cntr_num)
		return 0;

	entry = genradix_ptr_alloc(&ctx->list, ctx->base.count++,
				   GFP_ATOMIC);
	if (!entry) {
		ctx->base.count--;
		return -ENOMEM;
	}

	strscpy(entry->jsde_source, obd->obd_name,
		sizeof(entry->jsde_source));
	entry->jsde_obd = obd;
	entry->jsde_stats = &obd2obt(obd)->obt_jobstats;
	class_incref(obd, "netlink_job_stats", current);
	return 0;
}

static void job_stats_release(void *ventry)
{
	struct job_stats_dev_entry *entry = ventry;

	if (entry->jsde_obd)
		class_decref(entry->jsde_obd,
			     "netlink_job_stats", current);
}

static const struct ln_key_list *job_stats_keys[] = {
	&job_stats_list, &job_stats_dataset_list, NULL
};

static const struct lustre_nl_obd_ops job_stats_ops = {
	.refname	= "netlink_job_stats",
	.filter_key	= "source",
	.family		= &target_family,
	.entry_size	= sizeof(struct job_stats_dev_entry),
	.ctx_size	= sizeof(struct job_stats_ctx),
	.list_offset	= offsetof(struct job_stats_ctx, list),
	.cmd		= TARGET_CMD_JOB_STATS,
	.keys		= job_stats_keys,
	.device_match	= obd_is_server_type_match,
	.collect	= job_stats_collect,
	.release	= job_stats_release,
	/* .dump_one = NULL — uses custom lustre_job_stats_dump */
};

static int lustre_job_stats_start(struct netlink_callback *cb)
{
	return lustre_obd_nl_start(cb, &job_stats_ops);
}

static int lustre_job_stats_dump(struct sk_buff *msg,
				 struct netlink_callback *cb)
{
	struct job_stats_ctx *ctx =
		(struct job_stats_ctx *)cb->args[0];
	struct netlink_ext_ack *extack = cb->extack;
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int rc = 0;

	if (!ctx->base.key_sent) {
		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&target_family,
						NLM_F_CREATE | NLM_F_MULTI,
						TARGET_CMD_JOB_STATS,
						job_stats_keys);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			GOTO(send_err, rc);
		}
		ctx->base.key_sent = true;
	}

	while (ctx->base.index < ctx->base.count) {
		struct job_stats_dev_entry *entry;
		struct obd_job_stats *stats;
		struct rb_node *node;

		entry = genradix_ptr(&ctx->list, ctx->base.index);
		if (!entry) {
			ctx->base.index++;
			ctx->job_pos = 0;
			continue;
		}

		stats = entry->jsde_stats;
		down_read(&stats->ojs_rwsem);

		/* Find starting position in the postree */
		node = rb_first(&stats->ojs_postree);
		while (node) {
			struct job_stat *job;

			job = container_of(node, struct job_stat,
					   js_posnode);
			if (job->js_pos_id >= ctx->job_pos)
				break;
			node = rb_next(node);
		}

		while (node) {
			struct job_stat *job;
			struct lprocfs_stats *s;
			void *hdr;

			job = container_of(node, struct job_stat,
					   js_posnode);
			node = rb_next(node);

			if (test_bit(JS_EXPIRED, &job->js_flags))
				continue;

			hdr = genlmsg_put(msg, portid, seq,
					  &target_family,
					  NLM_F_MULTI,
					  TARGET_CMD_JOB_STATS);
			if (!hdr) {
				ctx->job_pos = job->js_pos_id;
				up_read(&stats->ojs_rwsem);
				GOTO(send_err, rc = 0);
			}

			if (!ctx->hdr_sent) {
				rc = nla_put_string(msg,
					LUSTRE_JOB_STATS_ATTR_HDR, "");
				if (rc) {
					genlmsg_cancel(msg, hdr);
					ctx->job_pos = job->js_pos_id;
					up_read(&stats->ojs_rwsem);
					GOTO(send_err, rc);
				}
				ctx->hdr_sent = true;
			}

			if (nla_put_string(msg,
					   LUSTRE_JOB_STATS_ATTR_SOURCE,
					   entry->jsde_source) ||
			    nla_put_string(msg,
					   LUSTRE_JOB_STATS_ATTR_JOBID,
					   job->js_jobid)) {
				genlmsg_cancel(msg, hdr);
				ctx->job_pos = job->js_pos_id;
				up_read(&stats->ojs_rwsem);
				GOTO(send_err, rc = -EMSGSIZE);
			}

			s = job->js_stats;
			if (nla_put_s64(msg,
					LUSTRE_JOB_STATS_ATTR_SNAPSHOT_TIME,
					ktime_to_ns(job->js_time_latest),
					LUSTRE_JOB_STATS_ATTR_PAD) ||
			    nla_put_s64(msg,
					LUSTRE_JOB_STATS_ATTR_START_TIME,
					ktime_to_ns(s->ls_init),
					LUSTRE_JOB_STATS_ATTR_PAD) ||
			    nla_put_s64(msg,
					LUSTRE_JOB_STATS_ATTR_ELAPSED_TIME,
					ktime_to_ns(ktime_sub(ktime_get_real(),
							      s->ls_init)),
					LUSTRE_JOB_STATS_ATTR_PAD)) {
				genlmsg_cancel(msg, hdr);
				ctx->job_pos = job->js_pos_id;
				up_read(&stats->ojs_rwsem);
				GOTO(send_err, rc = -EMSGSIZE);
			}

			rc = lustre_nl_put_dataset(msg, s,
					LUSTRE_JOB_STATS_ATTR_DATASET);
			if (rc) {
				genlmsg_cancel(msg, hdr);
				ctx->job_pos = job->js_pos_id;
				up_read(&stats->ojs_rwsem);
				GOTO(send_err, rc);
			}

			genlmsg_end(msg, hdr);
			ctx->job_pos = job->js_pos_id + 1;
		}

		up_read(&stats->ojs_rwsem);
		ctx->base.index++;
		ctx->job_pos = 0;
	}

send_err:
	return rc;
}

static int lustre_job_stats_done(struct netlink_callback *cb)
{
	return lustre_obd_nl_done(cb);
}

/* "target" genetlink family — server-only commands */

static const struct genl_multicast_group target_mcast_grps[] = {
	{ .name = "recovery_status" },
	{ .name = "brw_stats" },
	{ .name = "job_stats" },
	{ .name = "obd_params" },
	{ .name = "exports" },
};

static const struct genl_ops target_genl_ops[] = {
	{
		.cmd	= TARGET_CMD_RECOVERY,
		.start	= lustre_recovery_start,
		.dumpit	= lustre_recovery_dump,
		.done	= lustre_recovery_done,
	},
	{
		.cmd	= TARGET_CMD_BRW_STATS,
		.start	= lustre_brw_stats_start,
		.dumpit	= lustre_brw_stats_dump,
		.done	= lustre_brw_stats_done,
	},
	{
		.cmd	= TARGET_CMD_JOB_STATS,
		.start	= lustre_job_stats_start,
		.dumpit	= lustre_job_stats_dump,
		.done	= lustre_job_stats_done,
	},
	{
		.cmd	= TARGET_CMD_OBD_PARAMS,
		.start	= lustre_obd_params_start,
		.dumpit	= lustre_obd_params_dump,
		.done	= lustre_obd_params_done,
	},
	{
		.cmd	= TARGET_CMD_EXPORTS,
		.start	= lustre_export_start,
		.dumpit	= lustre_export_dump,
		.done	= lustre_export_done,
	},
};

static struct genl_family target_family = {
	.name		= TARGET_GENL_NAME,
	.version	= TARGET_GENL_VERSION,
	.module		= THIS_MODULE,
	.ops		= target_genl_ops,
	.n_ops		= ARRAY_SIZE(target_genl_ops),
	.mcgrps		= target_mcast_grps,
	.n_mcgrps	= ARRAY_SIZE(target_mcast_grps),
#ifdef GENL_FAMILY_HAS_RESV_START_OP
	.resv_start_op	= __TARGET_CMD_MAX_PLUS_ONE,
#endif
};

int lustre_target_nl_init(void)
{
	return genl_register_family(&target_family);
}

void lustre_target_nl_fini(void)
{
	genl_unregister_family(&target_family);
}
