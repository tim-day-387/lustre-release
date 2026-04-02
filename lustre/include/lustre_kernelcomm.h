/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 *
 * Kernel <-> userspace communication routines.
 * The definitions below are used in the kernel and userspace.
 */

#ifndef __LUSTRE_KERNELCOMM_H__
#define __LUSTRE_KERNELCOMM_H__

#include <linux/generic-radix-tree.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include <uapi/linux/lustre/lustre_kernelcomm.h>
#include <uapi/linux/lustre/lustre_user.h>

struct obd_device;
struct lprocfs_stats;

/**
 * enum lustre_device_attrs	      - Lustre general top-level netlink
 *					attributes that describe lustre
 *					'devices'. These values are used
 *					to piece together messages for
 *					sending and receiving.
 *
 * @LUSTRE_DEVICE_ATTR_UNSPEC:		unspecified attribute to catch errors
 *
 * @LUSTRE_DEVICE_ATTR_HDR:		Netlink group this data is for
 *					(NLA_NUL_STRING)
 * @LUSTRE_DEVICE_ATTR_INDEX:		device number used as an index (NLA_U16)
 * @LUSTRE_DEVICE_ATTR_STATUS:		status of the device (NLA_STRING)
 * @LUSTRE_DEVICE_ATTR_CLASS:		class the device belongs to (NLA_STRING)
 * @LUSTRE_DEVICE_ATTR_NAME:		name of the device (NLA_STRING)
 * @LUSTRE_DEVICE_ATTR_UUID:		UUID of the device (NLA_STRING)
 * @LUSTRE_DEVICE_ATTR_REFCOUNT:	refcount of the device (NLA_U32)
 */
enum lustre_device_attrs {
	LUSTRE_DEVICE_ATTR_UNSPEC = 0,

	LUSTRE_DEVICE_ATTR_HDR,
	LUSTRE_DEVICE_ATTR_INDEX,
	LUSTRE_DEVICE_ATTR_STATUS,
	LUSTRE_DEVICE_ATTR_CLASS,
	LUSTRE_DEVICE_ATTR_NAME,
	LUSTRE_DEVICE_ATTR_UUID,
	LUSTRE_DEVICE_ATTR_REFCOUNT,

	__LUSTRE_DEVICE_ATTR_MAX_PLUS_ONE
};

#define LUSTRE_DEVICE_ATTR_MAX (__LUSTRE_DEVICE_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_param_list_attrs	      - General header to list all sources
 *					supporting an specific query.
 *
 * @LUSTRE_PARAM_ATTR_UNSPEC:		unspecified attribute to catch errors
 *
 * @LUSTRE_PARAM_ATTR_HDR:		groups params belong to (NLA_NUL_STRING)
 * @LUSTRE_PARAM_ATTR_SOURCE:		source of the params (NLA_STRING)
 */
enum lustre_param_list_attrs {
	LUSTRE_PARAM_ATTR_UNSPEC = 0,

	LUSTRE_PARAM_ATTR_HDR,
	LUSTRE_PARAM_ATTR_SOURCE,

	__LUSTRE_PARAM_ATTR_MAX_PLUS_ONE
};

#define LUSTRE_PARAM_ATTR_MAX (__LUSTRE_PARAM_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_stats_attrs	     - Lustre stats netlink attributes used
 *				       to compose messages for sending or
 *				       receiving.
 *
 * @LUSTRE_STATS_ATTR_UNSPEC:	       unspecified attribute to catch errors
 * @LUSTRE_STATS_ATTR_PAD:	       padding for 64-bit attributes, ignore
 *
 * @LUSTRE_STATS_ATTR_HDR:	       groups stats belong to (NLA_NUL_STRING)
 * @LUSTRE_STATS_ATTR_SOURCE:	       source of the stats (NLA_STRING)
 * @LUSTRE_STATS_ATTR_TIMESTAMP:       time of collection in nanoseconds
 *				       (NLA_S64)
 * @LUSTRE_STATS_ATTR_START_TIME:      start time of collection (NLA_S64)
 * @LUSTRE_STATS_ATTR_ELAPSED_TIME:    elapsed time of collection (NLA_S64)
 * @LUSTRE_STATS_ATTR_DATASET:	       bookmarks for that stats data
 *				       (NLA_NESTED)
 */
enum lustre_stats_attrs {
	LUSTRE_STATS_ATTR_UNSPEC = 0,
	LUSTRE_STATS_ATTR_PAD = LUSTRE_STATS_ATTR_UNSPEC,

	LUSTRE_STATS_ATTR_HDR,
	LUSTRE_STATS_ATTR_SOURCE,
	LUSTRE_STATS_ATTR_TIMESTAMP,
	LUSTRE_STATS_ATTR_START_TIME,
	LUSTRE_STATS_ATTR_ELAPSE_TIME,
	LUSTRE_STATS_ATTR_DATASET,

	__LUSTRE_STATS_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_STATS_ATTR_MAX	(__LUSTRE_STATS_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_stats_dataset_attrs    - Lustre stats counter's netlink
 *					attributes used to compose messages
 *					for sending or receiving.
 *
 * @LUSTRE_STATS_ATTR_DATASET_UNSPEC:	unspecified attribute to catch errors
 * @LUSTRE_STATS_ATTR_DATASET_PAD:	padding for 64-bit attributes, ignore
 *
 * @LUSTRE_STATS_ATTR_DATASET_NAME:	name of counter (NLA_NUL_STRING)
 * @LUSTRE_STATS_ATTR_DATASET_COUNT:	counter interation (NLA_U64)
 * @LUSTRE_STATS_ATTR_DATASET_UNITS:	units of counter values (NLA_STRING)
 * @LUSTRE_STATS_ATTR_DATASET_MINIMUM:	smallest counter value collected
 *					(NLA_U64)
 * @LUSTRE_STATS_ATTR_DATASET_MAXIMUM:	largest count value collected (NLA_U64)
 * @LUSTRE_STATS_ATTR_DATASET_SUM:	total of all values of the counter
 *					(NLA_U64)
 * @LUSTRE_STATS_ATTR_DATASET_SUMSQUARE: Sum of the square of all values.
 *					 Allows user land apps to calculate
 *					 standard deviation. (NLA_U64)
 */
enum lustre_stats_dataset_attrs {
	LUSTRE_STATS_ATTR_DATASET_UNSPEC = 0,
	LUSTRE_STATS_ATTR_DATASET_PAD = LUSTRE_STATS_ATTR_DATASET_UNSPEC,

	LUSTRE_STATS_ATTR_DATASET_NAME,
	LUSTRE_STATS_ATTR_DATASET_COUNT,
	LUSTRE_STATS_ATTR_DATASET_UNITS,
	LUSTRE_STATS_ATTR_DATASET_MINIMUM,
	LUSTRE_STATS_ATTR_DATASET_MAXIMUM,
	LUSTRE_STATS_ATTR_DATASET_SUM,
	LUSTRE_STATS_ATTR_DATASET_SUMSQUARE,

	__LUSTRE_STATS_ATTR_DATASET_MAX_PLUS_ONE,
};

#define LUSTRE_STATS_ATTR_DATASET_MAX	(__LUSTRE_STATS_ATTR_DATASET_MAX_PLUS_ONE - 1)

struct lustre_stats_list {
	GENRADIX(struct lprocfs_stats *)	gfl_list;
	unsigned int				gfl_count;
	unsigned int				gfl_index;
};

unsigned int lustre_stats_scan(struct lustre_stats_list *slist, const char *filter);
int lustre_stats_dump(struct sk_buff *msg, struct netlink_callback *cb);
int lustre_stats_done(struct netlink_callback *cb);

/**
 * enum lustre_target_attrs	      - Lustre general top-level netlink
 *					attributes that describe lustre
 *					'target_obd'. These values are used
 *					to piece together messages for
 *					sending and receiving.
 *
 * @LUSTRE_TARGET_ATTR_UNSPEC:		unspecified attribute to catch errors
 *
 * @LUSTRE_TARGET_ATTR_HDR:		Netlink group this data is for
 *					(NLA_NUL_STRING)
 * @LUSTRE_TARGET_ATTR_SOURCE:		obd device targets belong too
 *					(NLA_STRING)
 * @LUSTRE_TARGET_ATTR_PROP_LIST:	list of target properties (NLA_NESTED)
 */
enum lustre_target_attrs {
	LUSTRE_TARGET_ATTR_UNSPEC = 0,

	LUSTRE_TARGET_ATTR_HDR,
	LUSTRE_TARGET_ATTR_SOURCE,
	LUSTRE_TARGET_ATTR_PROP_LIST,

	__LUSTRE_TARGET_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_TARGET_ATTR_MAX	(__LUSTRE_TARGET_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_target_props_attrs
 *
 * @LUSTRE_TARGET_PROP_ATTR_UNSPEC:	unspecified attribute to catch errors
 * @LUSTRE_TARGET_PROP_ATTR_INDEX:	target number used as an index (NLA_U16)
 * @LUSTRE_DEVICE_PROP_ATTR_UUID:	UUID of the target (NLA_STRING)
 * @LUSTRE_DEVICE_PROP_ATTR_STATUS:	status of the target (NLA_STRING)
 */
enum lustre_target_prop_attrs {
	LUSTRE_TARGET_PROP_ATTR_UNSPEC = 0,

	LUSTRE_TARGET_PROP_ATTR_INDEX,
	LUSTRE_TARGET_PROP_ATTR_UUID,
	LUSTRE_TARGET_PROP_ATTR_STATUS,

	__LUSTRE_TARGET_PROP_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_TARGET_PROP_ATTR_MAX	(__LUSTRE_TARGET_PROP_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_health_attrs	      - Lustre health netlink attributes
 *
 * @LUSTRE_HEALTH_ATTR_UNSPEC:		unspecified attribute to catch errors
 * @LUSTRE_HEALTH_ATTR_PAD:		padding for 64-bit attributes, ignore
 *
 * @LUSTRE_HEALTH_ATTR_HDR:		header for health data (NLA_NUL_STRING)
 * @LUSTRE_HEALTH_ATTR_HEALTHY:		health status (NLA_U8, 1=healthy)
 * @LUSTRE_HEALTH_ATTR_MEMUSED:		current OBD memory in bytes (NLA_U64)
 * @LUSTRE_HEALTH_ATTR_MEMUSED_MAX:	peak OBD memory in bytes (NLA_U64)
 * @LUSTRE_HEALTH_ATTR_LNET_MEMUSED:	current LNet memory in bytes (NLA_U64)
 * @LUSTRE_HEALTH_ATTR_UNHEALTHY_DEVS:	space-separated names of unhealthy
 *					OBD devices (NLA_NUL_STRING)
 */
enum lustre_health_attrs {
	LUSTRE_HEALTH_ATTR_UNSPEC	= 0,
	LUSTRE_HEALTH_ATTR_PAD		= LUSTRE_HEALTH_ATTR_UNSPEC,

	LUSTRE_HEALTH_ATTR_HDR		= 1,
	LUSTRE_HEALTH_ATTR_HEALTHY	= 2,
	LUSTRE_HEALTH_ATTR_MEMUSED	= 3,
	LUSTRE_HEALTH_ATTR_MEMUSED_MAX	= 4,
	LUSTRE_HEALTH_ATTR_LNET_MEMUSED	= 5,
	LUSTRE_HEALTH_ATTR_UNHEALTHY_DEVS = 6,

	__LUSTRE_HEALTH_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_HEALTH_ATTR_MAX	(__LUSTRE_HEALTH_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_recovery_attrs	      - Lustre recovery status netlink
 *					attributes
 *
 * @LUSTRE_RECOVERY_ATTR_UNSPEC:	unspecified attribute to catch errors
 * @LUSTRE_RECOVERY_ATTR_PAD:		padding for 64-bit attributes, ignore
 *
 * @LUSTRE_RECOVERY_ATTR_HDR:		recovery data header (NLA_NUL_STRING)
 * @LUSTRE_RECOVERY_ATTR_SOURCE:	OBD device name (NLA_STRING)
 * @LUSTRE_RECOVERY_ATTR_STATUS:	recovery state string (NLA_STRING)
 * @LUSTRE_RECOVERY_ATTR_DURATION:	recovery duration in seconds (NLA_S64)
 * @LUSTRE_RECOVERY_ATTR_TIME_REMAINING: seconds left in recovery (NLA_S64)
 * @LUSTRE_RECOVERY_ATTR_CONNECTED_CLIENTS: connected client count (NLA_U32)
 * @LUSTRE_RECOVERY_ATTR_COMPLETED_CLIENTS: completed client count (NLA_U32)
 * @LUSTRE_RECOVERY_ATTR_EVICTED_CLIENTS: evicted client count (NLA_U32)
 * @LUSTRE_RECOVERY_ATTR_MAX_CLIENTS:	max recoverable clients (NLA_U32)
 * @LUSTRE_RECOVERY_ATTR_REPLAYED_REQUESTS: replayed request count (NLA_U32)
 * @LUSTRE_RECOVERY_ATTR_QUEUED_REQUESTS: queued request count (NLA_U32)
 * @LUSTRE_RECOVERY_ATTR_NEXT_TRANSNO:	next expected transaction (NLA_U64)
 * @LUSTRE_RECOVERY_ATTR_VBR:		VBR enabled (NLA_U8, 1=enabled)
 * @LUSTRE_RECOVERY_ATTR_IR:		IR enabled (NLA_U8, 1=enabled)
 */
enum lustre_recovery_attrs {
	LUSTRE_RECOVERY_ATTR_UNSPEC		= 0,
	LUSTRE_RECOVERY_ATTR_PAD		= LUSTRE_RECOVERY_ATTR_UNSPEC,

	LUSTRE_RECOVERY_ATTR_HDR		= 1,
	LUSTRE_RECOVERY_ATTR_SOURCE		= 2,
	LUSTRE_RECOVERY_ATTR_STATUS		= 3,
	LUSTRE_RECOVERY_ATTR_DURATION		= 4,
	LUSTRE_RECOVERY_ATTR_TIME_REMAINING	= 5,
	LUSTRE_RECOVERY_ATTR_CONNECTED_CLIENTS	= 6,
	LUSTRE_RECOVERY_ATTR_COMPLETED_CLIENTS	= 7,
	LUSTRE_RECOVERY_ATTR_EVICTED_CLIENTS	= 8,
	LUSTRE_RECOVERY_ATTR_MAX_CLIENTS	= 9,
	LUSTRE_RECOVERY_ATTR_REPLAYED_REQUESTS	= 10,
	LUSTRE_RECOVERY_ATTR_QUEUED_REQUESTS	= 11,
	LUSTRE_RECOVERY_ATTR_NEXT_TRANSNO	= 12,
	LUSTRE_RECOVERY_ATTR_VBR		= 13,
	LUSTRE_RECOVERY_ATTR_IR			= 14,

	__LUSTRE_RECOVERY_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_RECOVERY_ATTR_MAX \
	(__LUSTRE_RECOVERY_ATTR_MAX_PLUS_ONE - 1)


/**
 * enum lustre_ldlm_attrs	      - Lustre LDLM lock stats netlink
 *					attributes
 *
 * @LUSTRE_LDLM_ATTR_UNSPEC:		unspecified attribute to catch errors
 * @LUSTRE_LDLM_ATTR_PAD:		padding for 64-bit attributes, ignore
 *
 * @LUSTRE_LDLM_ATTR_HDR:		header (NLA_NUL_STRING)
 * @LUSTRE_LDLM_ATTR_NAMESPACE:	lock namespace name (NLA_STRING)
 * @LUSTRE_LDLM_ATTR_CONTENDED_LOCKS: contention threshold (NLA_U32)
 * @LUSTRE_LDLM_ATTR_CONTENTION_SECONDS: contention time seconds (NLA_U32)
 * @LUSTRE_LDLM_ATTR_MAX_NOLOCK_BYTES: max no-lock I/O bytes (NLA_U32)
 * @LUSTRE_LDLM_ATTR_MAX_PARALLEL_AST: max parallel AST count (NLA_U32)
 * @LUSTRE_LDLM_ATTR_LRU_SIZE:	current LRU size (NLA_U32)
 * @LUSTRE_LDLM_ATTR_LRU_MAX:		max LRU size (NLA_U32)
 * @LUSTRE_LDLM_ATTR_LRU_MAX_AGE:	max LRU age in seconds (NLA_U64)
 * @LUSTRE_LDLM_ATTR_TIMEOUTS:	number of AST timeout evictions (NLA_U32)
 * @LUSTRE_LDLM_ATTR_LOCK_STATS:	per-ns lock statistics (NLA_NESTED)
 */
enum lustre_ldlm_attrs {
	LUSTRE_LDLM_ATTR_UNSPEC		= 0,
	LUSTRE_LDLM_ATTR_PAD			= LUSTRE_LDLM_ATTR_UNSPEC,

	LUSTRE_LDLM_ATTR_HDR			= 1,
	LUSTRE_LDLM_ATTR_NAMESPACE		= 2,
	LUSTRE_LDLM_ATTR_CONTENDED_LOCKS	= 3,
	LUSTRE_LDLM_ATTR_CONTENTION_SECONDS	= 4,
	LUSTRE_LDLM_ATTR_MAX_NOLOCK_BYTES	= 5,
	LUSTRE_LDLM_ATTR_MAX_PARALLEL_AST	= 6,
	LUSTRE_LDLM_ATTR_LRU_SIZE		= 7,
	LUSTRE_LDLM_ATTR_LRU_MAX		= 8,
	LUSTRE_LDLM_ATTR_LRU_MAX_AGE		= 9,
	LUSTRE_LDLM_ATTR_TIMEOUTS		= 10,
	LUSTRE_LDLM_ATTR_LOCK_STATS		= 11,

	__LUSTRE_LDLM_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_LDLM_ATTR_MAX	(__LUSTRE_LDLM_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_obd_params_attrs	      - Lustre OBD scalar parameters
 *					netlink attributes
 *
 * @LUSTRE_OBD_PARAMS_ATTR_UNSPEC:	unspecified attribute to catch errors
 * @LUSTRE_OBD_PARAMS_ATTR_PAD:	padding for 64-bit attributes, ignore
 *
 * @LUSTRE_OBD_PARAMS_ATTR_HDR:	header (NLA_NUL_STRING)
 * @LUSTRE_OBD_PARAMS_ATTR_SOURCE:	OBD device name (NLA_STRING)
 * @LUSTRE_OBD_PARAMS_ATTR_CLASS:	device type name (NLA_STRING)
 * @LUSTRE_OBD_PARAMS_ATTR_KBYTES_TOTAL: total space in KB (NLA_U64)
 * @LUSTRE_OBD_PARAMS_ATTR_KBYTES_FREE: free space in KB (NLA_U64)
 * @LUSTRE_OBD_PARAMS_ATTR_KBYTES_AVAIL: available space in KB (NLA_U64)
 * @LUSTRE_OBD_PARAMS_ATTR_FILES_TOTAL: total inodes (NLA_U64)
 * @LUSTRE_OBD_PARAMS_ATTR_FILES_FREE: free inodes (NLA_U64)
 * @LUSTRE_OBD_PARAMS_ATTR_NUM_EXPORTS: connected export count (NLA_U32)
 * @LUSTRE_OBD_PARAMS_ATTR_TOT_DIRTY: total dirty bytes (NLA_U64)
 * @LUSTRE_OBD_PARAMS_ATTR_TOT_GRANTED: total granted bytes (NLA_U64)
 * @LUSTRE_OBD_PARAMS_ATTR_TOT_PENDING: total pending bytes (NLA_U64)
 */
enum lustre_obd_params_attrs {
	LUSTRE_OBD_PARAMS_ATTR_UNSPEC		= 0,
	LUSTRE_OBD_PARAMS_ATTR_PAD		= LUSTRE_OBD_PARAMS_ATTR_UNSPEC,

	LUSTRE_OBD_PARAMS_ATTR_HDR		= 1,
	LUSTRE_OBD_PARAMS_ATTR_SOURCE		= 2,
	LUSTRE_OBD_PARAMS_ATTR_CLASS		= 3,
	LUSTRE_OBD_PARAMS_ATTR_KBYTES_TOTAL	= 4,
	LUSTRE_OBD_PARAMS_ATTR_KBYTES_FREE	= 5,
	LUSTRE_OBD_PARAMS_ATTR_KBYTES_AVAIL	= 6,
	LUSTRE_OBD_PARAMS_ATTR_FILES_TOTAL	= 7,
	LUSTRE_OBD_PARAMS_ATTR_FILES_FREE	= 8,
	LUSTRE_OBD_PARAMS_ATTR_NUM_EXPORTS	= 9,
	LUSTRE_OBD_PARAMS_ATTR_TOT_DIRTY	= 10,
	LUSTRE_OBD_PARAMS_ATTR_TOT_GRANTED	= 11,
	LUSTRE_OBD_PARAMS_ATTR_TOT_PENDING	= 12,

	__LUSTRE_OBD_PARAMS_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_OBD_PARAMS_ATTR_MAX \
	(__LUSTRE_OBD_PARAMS_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_brw_stats_attrs	      - Lustre BRW histogram netlink
 *					attributes
 *
 * @LUSTRE_BRW_STATS_ATTR_UNSPEC:	unspecified attribute to catch errors
 * @LUSTRE_BRW_STATS_ATTR_PAD:		padding for 64-bit attributes, ignore
 *
 * @LUSTRE_BRW_STATS_ATTR_HDR:		header (NLA_NUL_STRING)
 * @LUSTRE_BRW_STATS_ATTR_SOURCE:	OBD device name (NLA_STRING)
 * @LUSTRE_BRW_STATS_ATTR_TIMESTAMP:	time of collection in nanoseconds
 *					(NLA_S64)
 * @LUSTRE_BRW_STATS_ATTR_HISTOGRAM:	one histogram category (NLA_NESTED)
 */
enum lustre_brw_stats_attrs {
	LUSTRE_BRW_STATS_ATTR_UNSPEC		= 0,
	LUSTRE_BRW_STATS_ATTR_PAD		= LUSTRE_BRW_STATS_ATTR_UNSPEC,

	LUSTRE_BRW_STATS_ATTR_HDR		= 1,
	LUSTRE_BRW_STATS_ATTR_SOURCE		= 2,
	LUSTRE_BRW_STATS_ATTR_TIMESTAMP	= 3,
	LUSTRE_BRW_STATS_ATTR_HISTOGRAM	= 4,

	__LUSTRE_BRW_STATS_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_BRW_STATS_ATTR_MAX \
	(__LUSTRE_BRW_STATS_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_brw_hist_attrs	      - Lustre BRW histogram entry netlink
 *					attributes (nested inside
 *					LUSTRE_BRW_STATS_ATTR_HISTOGRAM)
 *
 * @LUSTRE_BRW_HIST_ATTR_UNSPEC:	unspecified attribute to catch errors
 * @LUSTRE_BRW_HIST_ATTR_PAD:		padding for 64-bit attributes, ignore
 *
 * @LUSTRE_BRW_HIST_ATTR_NAME:		histogram category name (NLA_STRING)
 * @LUSTRE_BRW_HIST_ATTR_UNITS:	bucket unit label (NLA_STRING)
 * @LUSTRE_BRW_HIST_ATTR_READ:	read buckets (NLA_NESTED of NLA_U64)
 * @LUSTRE_BRW_HIST_ATTR_WRITE:	write bucket values (NLA_NESTED of NLA_U64)
 */
enum lustre_brw_hist_attrs {
	LUSTRE_BRW_HIST_ATTR_UNSPEC		= 0,
	LUSTRE_BRW_HIST_ATTR_PAD		= LUSTRE_BRW_HIST_ATTR_UNSPEC,

	LUSTRE_BRW_HIST_ATTR_NAME		= 1,
	LUSTRE_BRW_HIST_ATTR_UNITS		= 2,
	LUSTRE_BRW_HIST_ATTR_READ		= 3,
	LUSTRE_BRW_HIST_ATTR_WRITE		= 4,

	__LUSTRE_BRW_HIST_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_BRW_HIST_ATTR_MAX \
	(__LUSTRE_BRW_HIST_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_export_attrs	      - Lustre per-client export stats
 *					netlink attributes
 *
 * @LUSTRE_EXPORT_ATTR_UNSPEC:		unspecified attribute to catch errors
 * @LUSTRE_EXPORT_ATTR_PAD:		padding for 64-bit attributes, ignore
 *
 * @LUSTRE_EXPORT_ATTR_HDR:		header (NLA_NUL_STRING)
 * @LUSTRE_EXPORT_ATTR_SOURCE:		OBD device name (NLA_STRING)
 * @LUSTRE_EXPORT_ATTR_NID:		client NID string (NLA_STRING)
 * @LUSTRE_EXPORT_ATTR_NODEMAP:		nodemap name for this NID (NLA_STRING)
 * @LUSTRE_EXPORT_ATTR_DATASET:		counter data (NLA_NESTED)
 */
enum lustre_export_attrs {
	LUSTRE_EXPORT_ATTR_UNSPEC	= 0,
	LUSTRE_EXPORT_ATTR_PAD		= LUSTRE_EXPORT_ATTR_UNSPEC,

	LUSTRE_EXPORT_ATTR_HDR		= 1,
	LUSTRE_EXPORT_ATTR_SOURCE	= 2,
	LUSTRE_EXPORT_ATTR_NID		= 3,
	LUSTRE_EXPORT_ATTR_NODEMAP	= 4,
	LUSTRE_EXPORT_ATTR_DATASET	= 5,

	__LUSTRE_EXPORT_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_EXPORT_ATTR_MAX	(__LUSTRE_EXPORT_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_job_stats_attrs	      - Lustre job stats netlink attributes
 *
 * @LUSTRE_JOB_STATS_ATTR_UNSPEC:	unspecified attribute to catch errors
 * @LUSTRE_JOB_STATS_ATTR_PAD:		padding for 64-bit attributes, ignore
 *
 * @LUSTRE_JOB_STATS_ATTR_HDR:		header (NLA_NUL_STRING)
 * @LUSTRE_JOB_STATS_ATTR_SOURCE:	OBD device name (NLA_STRING)
 * @LUSTRE_JOB_STATS_ATTR_JOBID:	job identifier (NLA_STRING)
 * @LUSTRE_JOB_STATS_ATTR_SNAPSHOT_TIME: time of last activity in ns (NLA_S64)
 * @LUSTRE_JOB_STATS_ATTR_START_TIME:	job start time in ns (NLA_S64)
 * @LUSTRE_JOB_STATS_ATTR_ELAPSED_TIME: elapsed time in ns (NLA_S64)
 * @LUSTRE_JOB_STATS_ATTR_DATASET:	counter data (NLA_NESTED)
 */
enum lustre_job_stats_attrs {
	LUSTRE_JOB_STATS_ATTR_UNSPEC		= 0,
	LUSTRE_JOB_STATS_ATTR_PAD		= LUSTRE_JOB_STATS_ATTR_UNSPEC,

	LUSTRE_JOB_STATS_ATTR_HDR		= 1,
	LUSTRE_JOB_STATS_ATTR_SOURCE		= 2,
	LUSTRE_JOB_STATS_ATTR_JOBID		= 3,
	LUSTRE_JOB_STATS_ATTR_SNAPSHOT_TIME	= 4,
	LUSTRE_JOB_STATS_ATTR_START_TIME	= 5,
	LUSTRE_JOB_STATS_ATTR_ELAPSED_TIME	= 6,
	LUSTRE_JOB_STATS_ATTR_DATASET		= 7,

	__LUSTRE_JOB_STATS_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_JOB_STATS_ATTR_MAX \
	(__LUSTRE_JOB_STATS_ATTR_MAX_PLUS_ONE - 1)


/**
 * enum lustre_changelog_attrs	      - Lustre changelog netlink attributes
 *
 * @LUSTRE_CHANGELOG_ATTR_UNSPEC:	unspecified attribute to catch errors
 * @LUSTRE_CHANGELOG_ATTR_PAD:		padding for 64-bit attributes, ignore
 *
 * @LUSTRE_CHANGELOG_ATTR_HDR:		header (NLA_NUL_STRING)
 * @LUSTRE_CHANGELOG_ATTR_SOURCE:	MDT device name (NLA_STRING)
 * @LUSTRE_CHANGELOG_ATTR_INDEX:	current changelog record index (NLA_U64)
 * @LUSTRE_CHANGELOG_ATTR_USERS:	changelog users (NLA_NESTED)
 */
enum lustre_changelog_attrs {
	LUSTRE_CHANGELOG_ATTR_UNSPEC	= 0,
	LUSTRE_CHANGELOG_ATTR_PAD	= LUSTRE_CHANGELOG_ATTR_UNSPEC,

	LUSTRE_CHANGELOG_ATTR_HDR	= 1,
	LUSTRE_CHANGELOG_ATTR_SOURCE	= 2,
	LUSTRE_CHANGELOG_ATTR_INDEX	= 3,
	LUSTRE_CHANGELOG_ATTR_USERS	= 4,

	__LUSTRE_CHANGELOG_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_CHANGELOG_ATTR_MAX \
	(__LUSTRE_CHANGELOG_ATTR_MAX_PLUS_ONE - 1)

/**
 * enum lustre_changelog_user_attrs   - Lustre changelog user netlink
 *					attributes (nested inside
 *					LUSTRE_CHANGELOG_ATTR_USERS)
 *
 * @LUSTRE_CHANGELOG_USER_ATTR_UNSPEC: unspecified attribute to catch errors
 * @LUSTRE_CHANGELOG_USER_ATTR_PAD:	padding for 64-bit attributes, ignore
 *
 * @LUSTRE_CHANGELOG_USER_ATTR_ID:	user name string (NLA_STRING)
 * @LUSTRE_CHANGELOG_USER_ATTR_INDEX:	last consumed record index (NLA_U64)
 * @LUSTRE_CHANGELOG_USER_ATTR_IDLE_SECS: seconds since last activity (NLA_U32)
 * @LUSTRE_CHANGELOG_USER_ATTR_MASK:	changelog event mask (NLA_U32)
 */
enum lustre_changelog_user_attrs {
	LUSTRE_CHANGELOG_USER_ATTR_UNSPEC	= 0,
	LUSTRE_CHANGELOG_USER_ATTR_PAD		= LUSTRE_CHANGELOG_USER_ATTR_UNSPEC,

	LUSTRE_CHANGELOG_USER_ATTR_ID		= 1,
	LUSTRE_CHANGELOG_USER_ATTR_INDEX	= 2,
	LUSTRE_CHANGELOG_USER_ATTR_IDLE_SECS	= 3,
	LUSTRE_CHANGELOG_USER_ATTR_MASK	= 4,

	__LUSTRE_CHANGELOG_USER_ATTR_MAX_PLUS_ONE,
};

#define LUSTRE_CHANGELOG_USER_ATTR_MAX \
	(__LUSTRE_CHANGELOG_USER_ATTR_MAX_PLUS_ONE - 1)

/* Changelog *user* state for netlink (not changelog records themselves).
 * Collected and dumped by mdd.ko via MDD_NL_CMD_CHANGELOG.
 * Two genradixes are used: one for per-MDT entries, one for all users.
 * Each entry stores a user_offset/num_users pair into the user genradix.
 */
struct changelog_nl_user {
	char	cnu_id[30]; /* CHANGELOG_USER_NAMELEN_FULL */
	__u16	cnu_pad;
	__u64	cnu_index;
	__u32	cnu_idle_secs;
	__u32	cnu_mask;
};

struct changelog_nl_entry {
	char	cne_source[MAX_OBD_NAME];
	__u64	cne_index;
	__u32	cne_num_users;
	__u32	cne_user_offset; /* start index in user genradix */
};

/* Typedefs required: each GENRADIX() expansion creates a distinct
 * anonymous struct type, so without a shared typedef the pointer types
 * are incompatible across translation units.
 */
typedef GENRADIX(struct changelog_nl_entry) changelog_entry_radix_t;
typedef GENRADIX(struct changelog_nl_user)  changelog_user_radix_t;

/* prototype for callback function on kuc groups */
typedef int (*libcfs_kkuc_cb_t)(void *data, void *cb_arg);

/* Kernel methods */
int libcfs_kkuc_init(void);
void libcfs_kkuc_fini(void);
int libcfs_kkuc_msg_put(struct file *fp, void *payload);
int libcfs_kkuc_group_put(const struct obd_uuid *uuid, int group, void *data);
int libcfs_kkuc_group_add(struct file *fp, const struct obd_uuid *uuid, int uid,
			  int group, void *data, size_t data_len);
int libcfs_kkuc_group_rem(const struct obd_uuid *uuid, int uid, int group);
int libcfs_kkuc_group_foreach(const struct obd_uuid *uuid, int group,
			      libcfs_kkuc_cb_t cb_func, void *cb_arg);

/*
 * Table-driven netlink handler framework.
 *
 * Commands that iterate OBD devices share a common start/dump/done
 * pattern.  Each command defines a static lustre_nl_obd_ops descriptor
 * and provides callbacks for the parts that differ.
 */
struct lustre_nl_ctx;

struct lustre_nl_obd_ops {
	const char		*refname;
	const char		*filter_key;
	const struct genl_family	*family;
	size_t			entry_size;
	size_t			ctx_size;
	size_t			list_offset;
	u32			min_alloc;
	int			cmd;
	const struct ln_key_list **keys;
	bool (*device_match)(struct obd_device *obd);
	const char *(*filter_target)(struct obd_device *obd);
	int  (*collect)(struct lustre_nl_ctx *ctx, struct obd_device *obd);
	void (*release)(void *entry);
	int  (*dump_one)(struct sk_buff *msg, void *entry, bool first);
};

struct lustre_nl_ctx {
	const struct lustre_nl_obd_ops	*ops;
	unsigned int			index;
	unsigned int			count;
	bool				key_sent;
};

static inline struct __genradix *
lustre_nl_genradix(struct lustre_nl_ctx *ctx)
{
	return (struct __genradix *)((char *)ctx + ctx->ops->list_offset);
}

static inline void *
lustre_nl_entry(struct lustre_nl_ctx *ctx, unsigned int idx)
{
	return __genradix_ptr(lustre_nl_genradix(ctx),
			      __idx_to_offset(idx, ctx->ops->entry_size));
}

int lustre_obd_nl_start(struct netlink_callback *cb,
			const struct lustre_nl_obd_ops *ops);
int lustre_obd_nl_dump(struct sk_buff *msg, struct netlink_callback *cb);
int lustre_obd_nl_done(struct netlink_callback *cb);
int lustre_nl_put_dataset(struct sk_buff *msg, struct lprocfs_stats *stats,
			  int base_attr);

extern struct genl_family lustre_family;
extern const struct ln_key_list stats_dataset_list;

int ldlm_netlink_init(void);
void ldlm_netlink_fini(void);

#ifdef HAVE_SERVER_SUPPORT
int lustre_target_nl_init(void);
void lustre_target_nl_fini(void);
#endif /* HAVE_SERVER_SUPPORT */

#endif /* __LUSTRE_KERNELCOMM_H__ */

