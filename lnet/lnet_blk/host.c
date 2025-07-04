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

#include <linux/completion.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/sysfb.h>
#include <linux/idr.h>

#include "common.h"

/* TODO: Check the size of the target */
unsigned long size_mb = 100;
module_param(size_mb, ulong, 0644);
MODULE_PARM_DESC(size_mb, "size of the block device (MB)");

static char *host_nid;
module_param(host_nid, charp, 0644);
MODULE_PARM_DESC(host_nid, "Source NID");

static char *target_nid;
module_param(target_nid, charp, 0644);
MODULE_PARM_DESC(target_nid, "Target NID");

static struct lnet_nid host_nid_blk;
static struct lnet_nid target_nid_blk;

struct lnet_blk_dev {
	sector_t capacity;
	u8 *data;
	struct blk_mq_tag_set tag_set;
	struct gendisk *disk;
	mempool_t *rq_mempool;
};

static struct lnet_blk_dev *lnet_blk_dev;
static DEFINE_IDA(blk_ram_indexes);
static int major;

static int LNetBlkPostActiveRdma(struct lnet_blk_rdma *rdma)
{
	struct lnet_process_id peer4 = rdma->ln_pid;
	struct lnet_handle_md *mdh = &rdma->ln_mdh;
	struct lnet_nid self = rdma->ln_self;
	u64 matchbits = rdma->ln_matchbits;
	int options = rdma->ln_options;
	int portal = rdma->ln_portal;
	struct lnet_processid peer;
	struct lnet_md md;
	int rc;

	lnet_pid4_to_pid(peer4, &peer);

	options |= LNET_MD_MANAGE_REMOTE | LNET_MD_KIOV;
	md.threshold = 2;
	md.options = options & ~(LNET_MD_OP_PUT | LNET_MD_OP_GET);
	md.user_ptr = rdma;
	md.start = rdma->ln_iov;
	md.length = rdma->ln_iov_cnt;
	md.handler = LNetIO_ev_handler;

	rc = LNetMDBind(&md, LNET_UNLINK, mdh);
	if (rc) {
		CERROR("LNetMDBind failed: %d\n", rc);
		LASSERT(rc == -ENOMEM);
		return -ENOMEM;
	}

	/* this is kind of an abuse of the LNET_MD_OP_{PUT,GET} options.
	 * they're only meaningful for MDs attached to an ME (i.e. passive
	 * buffers...
	 */
	if ((options & LNET_MD_OP_PUT) != 0) {
		rc = LNetPut(&self, *mdh, LNET_ACK_REQ, &peer,
			     portal, matchbits, rdma->ln_off, 0);
	} else if ((options & LNET_MD_OP_GET) != 0) {
		rc = LNetGet(&self, *mdh, &peer, portal, matchbits, rdma->ln_off, false);
	} else {
		CERROR("Invalid LNet operation: %d\n", rc);
		rc = -EINVAL;
	}

	if (rc) {
		CERROR("LNet%s(%s, %d, %lld) failed: %d\n",
		       ((options & LNET_MD_OP_PUT) != 0) ? "Put" : "Get",
		       libcfs_id2str(peer4), portal, matchbits, rc);

		/* The forthcoming unlink event will complete this operation
		 * with failure, so fall through and return success here.
		 */
		rc = LNetMDUnlink(*mdh);
		LASSERT(rc == 0);
	}

	CDEBUG(D_NET, "Posted active RDMA: peer %s, portal %u, matchbits %#llx, off %lld Op=%s\n",
	       libcfs_id2str(peer4), portal, matchbits, rdma->ln_off,
	       ((options & LNET_MD_OP_PUT) != 0) ? "PUT" : "GET");

	return 0;
}

/* TODO: Unify logic with target */
static int offset_to_matchbits(loff_t pos)
{
	int matchbits = 0;

	if (pos < SZ_1M)
		return matchbits;

	matchbits = DIV_ROUND_UP(pos, SZ_1M) - 1;

	if (pos % SZ_1M == 0)
		matchbits++;

	return matchbits;
}

static int LNetBlkFetch(struct lnet_blk_rdma *rdma)
{
	int rc = 0;

	init_completion(&rdma->ln_ev_comp);

	rc = LNetBlkPostActiveRdma(rdma);
	if (rc) {
		CERROR("LNetBlkPostActiveRdma failed: %d\n", rc);
		return rc;
	}

	wait_for_completion(&rdma->ln_ev_comp);

	return 0;
}

static blk_status_t lnet_blk_queue_rq(struct blk_mq_hw_ctx *hctx,
				      const struct blk_mq_queue_data *bd)
{
	struct lnet_blk_dev *blkram = hctx->queue->queuedata;
	loff_t data_len = (blkram->capacity << SECTOR_SHIFT);
	struct request *rq = bd->rq;
	loff_t pos = blk_rq_pos(rq) << SECTOR_SHIFT;
	struct lnet_blk_rdma *rdma = NULL;
	blk_status_t err = BLK_STS_OK;
	struct req_iterator iter;
	struct bio_vec bv;
	int max_iovs;
	int rc = 0;

	blk_mq_start_request(rq);

	if (pos + blk_rq_bytes(rq) > data_len) {
		err = BLK_STS_IOERR;
		goto end_request;
	}

	rdma = mempool_alloc(lnet_blk_dev->rq_mempool, __GFP_ZERO);
	if (!rdma) {
		err = BLK_STS_IOERR;
		goto end_request;
	}

	*rdma = (struct lnet_blk_rdma) {
		.ln_portal = RDMA_PORTAL,
		.ln_self = host_nid_blk,
		.ln_pid = (struct lnet_process_id) {
			.nid = lnet_nid_to_nid4(&target_nid_blk),
			.pid = LNET_PID_LUSTRE,
		},
		.ln_matchbits = offset_to_matchbits(pos) + 0x1000,
		.ln_off = pos % SZ_1M,
		.ln_active = true,
		.ln_iov_cnt = 0,
	};

	max_iovs = DIV_ROUND_UP(SZ_1M - rdma->ln_off, PAGE_SIZE);
	LASSERT(max_iovs <= LNET_MAX_IOV);

	switch (req_op(rq)) {
	case REQ_OP_READ:
		rdma->ln_options = LNET_MD_OP_GET;
		break;
	case REQ_OP_WRITE:
		rdma->ln_options = LNET_MD_OP_PUT;
		break;
	default:
		err = BLK_STS_IOERR;
		goto end_request;
	}

	rq_for_each_segment(bv, rq, iter) {
		rdma->ln_iov[rdma->ln_iov_cnt] = bv;
		rdma->ln_iov_cnt++;

		if (rdma->ln_iov_cnt == max_iovs) {
			rc = LNetBlkFetch(rdma);
			if (rc) {
				err = BLK_STS_IOERR;
				goto end_request;
			}

			pos += SZ_1M;

			rdma->ln_iov_cnt = 0;
			rdma->ln_matchbits = offset_to_matchbits(pos) + 0x1000;
			rdma->ln_off = 0;
			max_iovs = LNET_MAX_IOV;
		}
	}

	if (rdma->ln_iov_cnt) {
		rc = LNetBlkFetch(rdma);
		if (rc) {
			err = BLK_STS_IOERR;
			goto end_request;
		}
	}

end_request:
	mempool_free(rdma, lnet_blk_dev->rq_mempool);
	blk_mq_end_request(rq, err);

	return BLK_STS_OK;
}

static const struct block_device_operations lnet_blk_rq_ops = {
	.owner = THIS_MODULE,
};

static const struct blk_mq_ops lnet_blk_mq_ops = {
	.queue_rq = lnet_blk_queue_rq,
};

static int __init lnet_blk_host_init(void)
{
	loff_t size_bytes = size_mb << 20;
	struct queue_limits lim = { 0 };
	struct gendisk *disk;
	int rc = 0;
	int minor;

	LCONSOLE_INFO("Loading LNet block host!\n");

	libcfs_strnid(&host_nid_blk, host_nid);
	LASSERT(!LNET_NID_IS_ANY(&host_nid_blk));
	libcfs_strnid(&target_nid_blk, target_nid);
	LASSERT(!LNET_NID_IS_ANY(&target_nid_blk));

	rc = register_blkdev(0, "lnetblk");
	if (rc < 0)
		return rc;

	major = rc;

	CFS_ALLOC_PTR(lnet_blk_dev);
	if (!lnet_blk_dev) {
		rc = -ENOMEM;
		goto unreg_blk;
	}

	lnet_blk_dev->rq_mempool =
		mempool_create_kmalloc_pool(8 * 1024, sizeof(struct lnet_blk_rdma));
	if (!lnet_blk_dev->rq_mempool) {
		rc = -ENOMEM;
		goto free_blk_dev;
	}

	lnet_blk_dev->capacity = size_bytes >> SECTOR_SHIFT;

	lnet_blk_dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
	lnet_blk_dev->tag_set.driver_data = lnet_blk_dev;
	/* TODO: Get NUMA from cpt of NI */
	lnet_blk_dev->tag_set.numa_node = NUMA_NO_NODE;
	lnet_blk_dev->tag_set.ops = &lnet_blk_mq_ops;
	lnet_blk_dev->tag_set.queue_depth = 256;
	lnet_blk_dev->tag_set.nr_hw_queues = 1;
	lnet_blk_dev->tag_set.cmd_size = 0;

	rc = blk_mq_alloc_tag_set(&lnet_blk_dev->tag_set);
	if (rc)
		goto free_blk_dev;

	disk = blk_mq_alloc_disk(&lnet_blk_dev->tag_set, &lim, lnet_blk_dev);
	if (IS_ERR(disk)) {
		rc = PTR_ERR(disk);
		goto free_blk_dev;
	}

	lnet_blk_dev->disk = disk;

	/* TODO: Magic numbers, although sub-PAGE_SIZE
	 * lbs/pbs do not work
	 */
	lim = queue_limits_start_update(disk->queue);
	lim.features |= BLK_FEAT_PCI_P2PDMA;
	lim.physical_block_size = PAGE_SIZE;
	lim.logical_block_size = PAGE_SIZE;
	lim.max_segment_size = PAGE_SIZE;
	lim.max_hw_sectors = SZ_1M >> SECTOR_SHIFT;
	lim.max_segments = LNET_MAX_IOV;
	lim.io_min = SZ_1M;
	lim.io_opt = SZ_1M;

	rc = queue_limits_commit_update(disk->queue, &lim);
	if (rc)
		goto free_blk_dev;

	/* TODO: Support more than one disk */
	minor = rc = ida_alloc(&blk_ram_indexes, GFP_KERNEL);
	if (rc < 0)
		goto cleanup_disk;

	disk->flags = GENHD_FL_NO_PART;
	disk->fops = &lnet_blk_rq_ops;
	disk->first_minor = minor;
	disk->major = major;
	disk->minors = 1;

	snprintf(disk->disk_name, DISK_NAME_LEN, "lnetblk");
	set_capacity(disk, lnet_blk_dev->capacity);

	rc = add_disk(disk);
	if (rc < 0)
		goto cleanup_disk;

	return 0;

cleanup_disk:
	put_disk(lnet_blk_dev->disk);
free_blk_dev:
	CFS_FREE_PTR(lnet_blk_dev);
unreg_blk:
	unregister_blkdev(major, "lnetblk");

	return rc;
}

static void __exit lnet_blk_host_exit(void)
{
	LCONSOLE_INFO("Unloading LNet block host!\n");

	if (lnet_blk_dev->disk) {
		del_gendisk(lnet_blk_dev->disk);
		put_disk(lnet_blk_dev->disk);
	}

	mempool_destroy(lnet_blk_dev->rq_mempool);
	CFS_FREE_PTR(lnet_blk_dev);
	unregister_blkdev(major, "lnetblk");
}

MODULE_AUTHOR("Timothy Day <timday@amazon.com>");
MODULE_DESCRIPTION("LNet block host");
MODULE_LICENSE("GPL");

module_init(lnet_blk_host_init);
module_exit(lnet_blk_host_exit);
