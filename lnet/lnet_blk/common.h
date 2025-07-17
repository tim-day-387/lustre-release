/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Timothy Day <timday@amazon.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/bvec.h>

#include <libcfs/libcfs.h>
#include <lnet/api.h>
#include <lnet/lib-lnet.h>
#include <lnet/lib-types.h>

/* Arbitrary portal number */
#define RDMA_PORTAL 52

struct lnet_blk_rdma {
	int ln_portal;
	bool ln_active;

	struct lnet_nid ln_self;
	struct lnet_process_id ln_pid;
	struct lnet_handle_md ln_mdh;
	struct lnet_msg ln_msg;

	struct completion ln_ev_comp;

	struct bio_vec ln_iov[LNET_MAX_IOV];
	int ln_iov_cnt;
	int ln_len;
	struct request *ln_rq;

	loff_t ln_off;

	u64 ln_matchbits;
	int ln_options;
};

/* Intentionally unused - only for debugging */
static inline void lnet_blk_print_hex_dump(const char *prefix_str, struct bio_vec *iov)
{
	unsigned int len = iov->bv_len > 16 ? 16 : iov->bv_len;
	void *buf = page_address(iov->bv_page) + iov->bv_offset;

	print_hex_dump(KERN_INFO, prefix_str, DUMP_PREFIX_ADDRESS,
		       64, 1, buf, len, true);
}

static inline void lnet_blk_print_rdma(struct lnet_blk_rdma *rdma)
{
	unsigned int len = rdma->ln_iov->bv_len;
	void *buf = page_address(rdma->ln_iov->bv_page) + rdma->ln_iov->bv_offset;

	CDEBUG(D_NET, "RDMA portal[%i] buf[%p] len[%u]\n", rdma->ln_portal, buf, len);
}

void LNetIO_ev_handler(struct lnet_event *ev);
