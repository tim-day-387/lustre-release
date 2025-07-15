// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Timothy Day <timday@amazon.com>
 */

#include "common.h"

unsigned long size_mb = 100;
module_param(size_mb, ulong, 0644);
MODULE_PARM_DESC(size_mb, "size of the block device (MB)");

static int LNetBlkPostPassiveRdma(struct lnet_blk_rdma *rdma)
{
	unsigned int npages = DIV_ROUND_UP(rdma->ln_len, PAGE_SIZE);
	struct lnet_process_id peer4 = rdma->ln_pid;
	struct lnet_handle_md *mdh = &rdma->ln_mdh;
	u64 matchbits = rdma->ln_matchbits;
	int options = rdma->ln_options;
	int portal = rdma->ln_portal;
	struct lnet_processid peer;
	struct lnet_me *me;
	struct lnet_md md;
	int rc;

	peer.pid = peer4.pid;
	lnet_nid4_to_nid(peer4.nid, &peer.nid);

	me = LNetMEAttach(portal, &peer, matchbits, 0, LNET_RETAIN,
			  LNET_INS_AFTER);
	if (IS_ERR(me)) {
		rc = PTR_ERR(me);
		CERROR("LNetMEAttach failed: %d\n", rc);
		LASSERT(rc == -ENOMEM);
		return -ENOMEM;
	}

	options |= LNET_MD_MANAGE_REMOTE;
	md.umd_threshold = LNET_MD_THRESH_INF;
	md.umd_options = options | LNET_MD_KIOV;
	md.umd_user_ptr = rdma;
	md.umd_start = rdma->ln_iov;
	md.umd_length = npages;
	md.umd_handler = LNetIO_ev_handler;

	rc = LNetMDAttach(me, &md, LNET_RETAIN, mdh);
	if (rc) {
		CERROR("LNetMDAttach failed: %d\n", rc);
		LASSERT(rc == -ENOMEM);
		return -ENOMEM;
	}

	CDEBUG(D_NET, "Posted passive RDMA: peer %s, portal %d, matchbits %#llx\n",
	       libcfs_id2str(peer4), portal, matchbits);

	return 0;
}

static void free_bvec_array(struct bio_vec *iov, size_t len)
{
	unsigned int npages = DIV_ROUND_UP(len, PAGE_SIZE);
	unsigned int i;

	for (i = 0; i < npages; i++)
		if (iov[i].bv_page)
			__free_page(iov[i].bv_page);
}

static int alloc_bvec_array(struct bio_vec *iov, size_t len)
{
	unsigned int npages = DIV_ROUND_UP(len, PAGE_SIZE);
	struct page *page;
	unsigned int i;

	if (npages > LNET_MAX_IOV)
		return -EINVAL;

	for (i = 0; i < npages; i++) {
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			goto out_mem;

		bvec_set_page(&iov[i], page, PAGE_SIZE, 0);
	}

	return 0;

out_mem:
	free_bvec_array(iov, len);
	return -ENOMEM;
}

static int LNetBlkCreate(struct lnet_blk_rdma *rdma, int idx)
{
	int rc;

	*rdma = (struct lnet_blk_rdma) {
		.ln_portal = RDMA_PORTAL,
		.ln_pid = (struct lnet_process_id) {
			.nid = LNET_NID_ANY,
			.pid = LNET_PID_LUSTRE,
		},
		.ln_len = SZ_1M,
		.ln_matchbits = idx + 0x1000,
		.ln_options = LNET_MD_OP_GET | LNET_MD_OP_PUT,
		.ln_active = false,
	};

	rc = alloc_bvec_array(rdma->ln_iov, rdma->ln_len);
	if (rc)
		return rc;

	lnet_blk_print_rdma(rdma);

	rc = LNetBlkPostPassiveRdma(rdma);

	return rc;
}

static void LNetBlkDestroy(struct lnet_blk_rdma *rdma)
{
	free_bvec_array(rdma->ln_iov, rdma->ln_len);
}

static struct lnet_blk_rdma *rdma;

static int __init lnet_blk_target_init(void)
{
	struct lnet_nid self;
	int rc = 0;
	int i;

	LCONSOLE_INFO("Loading LNet block target!\n");

	LNetLocalPrimaryNID(&self);
	LASSERT(!LNET_NID_IS_ANY(&self));

	CFS_ALLOC_PTR_ARRAY(rdma, size_mb);
	if (!rdma)
		return -ENOMEM;

	for (i = 0; i < size_mb; i++) {
		rc = LNetBlkCreate(&rdma[i], i);
		if (rc)
			return rc;
	}

	return rc;
}

static void __exit lnet_blk_target_exit(void)
{
	int i;

	LCONSOLE_INFO("Unloading LNet block target!\n");

	for (i = 0; i < size_mb; i++)
		LNetBlkDestroy(&rdma[i]);

	CFS_FREE_PTR_ARRAY(rdma, size_mb);
}

MODULE_AUTHOR("Timothy Day <timday@amazon.com>");
MODULE_DESCRIPTION("LNet block target");
MODULE_LICENSE("GPL");

module_init(lnet_blk_target_init);
module_exit(lnet_blk_target_exit);
