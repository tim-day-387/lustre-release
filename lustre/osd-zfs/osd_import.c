// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2024, OpenSFS.
 *
 * ZFS pool import for Lustre root filesystem boot.
 *
 * Reads ZFS vdev labels from a block device and imports the pool
 * using spa_import(). This is triggered automatically by osd_objset_open()
 * when the pool is not yet imported (i.e., dmu_objset_own() fails).
 *
 * The block device path is specified via the osd_zfs.root_device module
 * parameter (typically set on the kernel command line).
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/blkdev.h>

#include "osd_internal.h"

#include <sys/spa.h>
#include <sys/nvpair.h>
#include <sys/fs/zfs.h>
#include <sys/vdev.h>
#include <sys/vdev_impl.h>

static char *osd_zfs_root_device;
module_param_named(root_device, osd_zfs_root_device, charp, 0444);
MODULE_PARM_DESC(root_device,
		 "Block device path for ZFS pool auto-import (e.g. /dev/sda3)");

/**
 * osd_zfs_read_label - Read ZFS label config from a block device
 * @device: path to the block device
 * @configp: Returns the nvlist config from the label
 *
 * Opens the block device and reads the ZFS vdev label to extract the
 * pool configuration. This is needed because spa_import requires the
 * actual pool/vdev GUIDs from the on-disk labels, not fabricated values.
 *
 * Return: 0 on success, negative error code on failure
 */
static int osd_zfs_read_label(const char *device, nvlist_t **configp)
{
	struct file *filp;
	vdev_phys_t *vp;
	loff_t offset;
	uint64_t psize;
	uint64_t state, txg;
	ssize_t ret;
	int l, rc;

	*configp = NULL;

	filp = bdev_file_open_by_path(device, BLK_OPEN_READ, NULL, NULL);
	if (IS_ERR(filp)) {
		rc = PTR_ERR(filp);
		pr_err("Lustre: Failed to open device %s: %d\n", device, rc);
		return rc;
	}

	/* Get device size */
	psize = i_size_read(file_inode(filp));
	if (psize == 0) {
		pr_err("Lustre: Device %s has zero size\n", device);
		rc = -EINVAL;
		goto out_close;
	}

	/* Align to label size */
	psize = P2ALIGN_TYPED(psize, sizeof(vdev_label_t), uint64_t);

	vp = kmem_alloc(sizeof(*vp), KM_SLEEP);
	if (!vp) {
		rc = -ENOMEM;
		goto out_close;
	}

	/*
	 * Try to read each of the 4 labels. Labels 0,1 are at the start,
	 * labels 2,3 are at the end. Use the first valid one we find.
	 */
	for (l = 0; l < VDEV_LABELS; l++) {
		nvlist_t *config;

		/*
		 * Calculate label offset. Labels 0,1 are at start,
		 * labels 2,3 are at end of device.
		 */
		offset = vdev_label_offset(psize, l, 0) + VDEV_SKIP_SIZE;

		ret = kernel_read(filp, vp, sizeof(*vp), &offset);
		if (ret != sizeof(*vp)) {
			pr_debug("Lustre: Failed to read label %d\n", l);
			continue;
		}

		/* Try to unpack the nvlist */
		rc = nvlist_unpack(vp->vp_nvlist, sizeof(vp->vp_nvlist),
				   &config, 0);
		if (rc != 0) {
			pr_debug("Lustre: Failed to unpack label %d nvlist\n", l);
			continue;
		}

		/* Validate the label */
		if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE,
					 &state) != 0 ||
		    state > POOL_STATE_L2CACHE) {
			nvlist_free(config);
			continue;
		}

		if (state != POOL_STATE_SPARE &&
		    state != POOL_STATE_L2CACHE &&
		    (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_TXG,
					  &txg) != 0 || txg == 0)) {
			nvlist_free(config);
			continue;
		}

		/* Found a valid label */
		pr_info("Lustre: Read valid ZFS label %d\n", l);
		*configp = config;
		rc = 0;
		goto out_free;
	}

	pr_err("Lustre: No valid ZFS labels found on %s\n", device);
	rc = -EINVAL;

out_free:
	kmem_free(vp, sizeof(*vp));
out_close:
	/*
	 * Use __fput_sync() to ensure the device is fully released before
	 * returning. This is important because spa_import() will try to
	 * open the device with exclusive access immediately after we return.
	 */
	__fput_sync(filp);
	return rc;
}

/**
 * osd_zfs_try_import_pool - Import a ZFS pool if the root device is configured
 * @pool: Pool name to import
 *
 * Called from osd_objset_open() when dmu_objset_own() fails, indicating the
 * pool may not be imported yet. Uses the device path from the root_device
 * module parameter to read the ZFS labels and import the pool.
 *
 * Return: 0 on success, negative error code on failure
 */
int osd_zfs_try_import_pool(const char *pool)
{
	const char *device = osd_zfs_root_device;
	nvlist_t *config = NULL;
	nvlist_t *nvroot = NULL;
	nvlist_t *nvtop = NULL;
	uint64_t pool_guid;
	const char *label_pool_name;
	int rc;

	if (!device || !device[0])
		return -ENODEV;

	pr_info("Lustre: Importing ZFS pool %s from %s\n", pool, device);

	/* Read the actual pool config from the device label */
	rc = osd_zfs_read_label(device, &config);
	if (rc)
		return rc;

	/* Verify this is the pool we expect */
	if (nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME,
				 &label_pool_name) != 0) {
		pr_err("Lustre: Label missing pool name\n");
		rc = -EINVAL;
		goto out;
	}

	if (strcmp(label_pool_name, pool) != 0) {
		pr_err("Lustre: Pool name mismatch: expected %s, found %s\n",
		       pool, label_pool_name);
		rc = -EINVAL;
		goto out;
	}

	/*
	 * The label config has the vdev tree directly. We need to wrap it
	 * in a root vdev for spa_import. The label contains:
	 *   ZPOOL_CONFIG_VDEV_TREE -> the top-level vdev (disk)
	 * We need:
	 *   ZPOOL_CONFIG_VDEV_TREE -> root vdev -> children[0] = disk vdev
	 */
	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE,
				 &nvtop) != 0) {
		pr_err("Lustre: Label missing vdev tree\n");
		rc = -EINVAL;
		goto out;
	}

	/* Duplicate the vdev tree since we'll remove it from config */
	nvtop = fnvlist_dup(nvtop);
	if (!nvtop) {
		rc = -ENOMEM;
		goto out;
	}

	/* Update the device path in case it differs from what's stored */
	fnvlist_remove(nvtop, ZPOOL_CONFIG_PATH);
	fnvlist_add_string(nvtop, ZPOOL_CONFIG_PATH, device);

	/*
	 * The pool may have been created with a file-backed vdev (type="file")
	 * and then written to a block device. We need to change the vdev type
	 * to "disk" so ZFS uses vdev_disk_ops instead of vdev_file_ops.
	 */
	fnvlist_remove(nvtop, ZPOOL_CONFIG_TYPE);
	fnvlist_add_string(nvtop, ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK);

	/* Get pool GUID for root vdev */
	if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
				 &pool_guid) != 0) {
		pr_err("Lustre: Label missing pool GUID\n");
		rc = -EINVAL;
		goto out;
	}

	/* Create root vdev to wrap the disk vdev */
	nvroot = fnvlist_alloc();
	if (!nvroot) {
		rc = -ENOMEM;
		goto out;
	}
	fnvlist_add_string(nvroot, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT);
	fnvlist_add_uint64(nvroot, ZPOOL_CONFIG_ID, 0);
	fnvlist_add_uint64(nvroot, ZPOOL_CONFIG_GUID, pool_guid);
	fnvlist_add_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN,
				 (const nvlist_t * const *)&nvtop, 1);

	/* Replace the vdev tree with our wrapped version */
	fnvlist_remove(config, ZPOOL_CONFIG_VDEV_TREE);
	fnvlist_add_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, nvroot);

	/* Import the pool */
	rc = spa_import((char *)pool, config, NULL, 0);
	if (rc) {
		pr_err("Lustre: spa_import failed for pool %s: %d\n", pool, rc);
		rc = -rc;  /* spa_import returns positive error codes */
		goto out;
	}

	pr_info("Lustre: ZFS pool %s imported successfully\n", pool);
	rc = 0;

out:
	if (nvtop)
		fnvlist_free(nvtop);
	if (nvroot)
		fnvlist_free(nvroot);
	if (config)
		fnvlist_free(config);
	return rc;
}
