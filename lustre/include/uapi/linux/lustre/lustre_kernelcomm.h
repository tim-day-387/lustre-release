/* SPDX-License-Identifier: LGPL-2.1+ WITH Linux-syscall-note */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Kernel <-> userspace communication routines.
 * The definitions below are used in the kernel and userspace.
 *
 * Author: Nathan Rutman <nathan.rutman@seagate.com>
 */

#ifndef __UAPI_KERNELCOMM_H__
#define __UAPI_KERNELCOMM_H__

#include <linux/types.h>

#define LUSTRE_GENL_NAME		"lustre"
#define LUSTRE_GENL_VERSION		0x2

/*
 * enum lustre_commands		      - Supported Lustre Netlink commands
 *
 * @LUSTRE_CMD_UNSPEC:			unspecified command to catch errors
 *
 * @LUSTRE_CMD_DEVICES:			command to manage the Lustre devices
 * @LUSTRE_CMD_KUC:			reserved for KUC
 * @LUSTRE_CMD_TARGETS:			command to manage the Lustre targets
 * @LUSTRE_CMD_IMPORT:			reserved for import
 * @LUSTRE_CMD_STATS:			Lustre stats collection command
 * @LUSTRE_CMD_POOL:			reserved for pool
 * @LUSTRE_CMD_HEALTH:			health and memory status
 * @LUSTRE_CMD_EXPORTS:			per-client export stats
 * @LUSTRE_CMD_OBD_PARAMS:		scalar OBD params (statfs, grants)
 */
enum lustre_commands {
	LUSTRE_CMD_UNSPEC	= 0,

	LUSTRE_CMD_DEVICES	= 1,
	LUSTRE_CMD_KUC		= 2,	/* reserved */
	LUSTRE_CMD_TARGETS	= 3,
	LUSTRE_CMD_IMPORT	= 4,	/* reserved */
	LUSTRE_CMD_STATS	= 5,
	LUSTRE_CMD_POOL		= 6,	/* reserved */
	LUSTRE_CMD_HEALTH	= 7,

	__LUSTRE_CMD_MAX_PLUS_ONE
};

#define LUSTRE_CMD_MAX	(__LUSTRE_CMD_MAX_PLUS_ONE - 1)

#define TARGET_GENL_NAME	"target"
#define TARGET_GENL_VERSION	0x01

enum target_commands {
	TARGET_CMD_UNSPEC	= 0,

	TARGET_CMD_RECOVERY	= 1,
	TARGET_CMD_BRW_STATS	= 2,
	TARGET_CMD_JOB_STATS	= 3,
	TARGET_CMD_OBD_PARAMS	= 4,
	TARGET_CMD_EXPORTS	= 5,

	__TARGET_CMD_MAX_PLUS_ONE
};

#define TARGET_CMD_MAX	(__TARGET_CMD_MAX_PLUS_ONE - 1)

#define LDLM_GENL_NAME		"ldlm"
#define LDLM_GENL_VERSION	0x01

enum ldlm_nl_commands {
	LDLM_NL_CMD_UNSPEC	= 0,

	LDLM_NL_CMD_STATS	= 1,

	__LDLM_NL_CMD_MAX_PLUS_ONE
};

#define LDLM_NL_CMD_MAX	(__LDLM_NL_CMD_MAX_PLUS_ONE - 1)

#define MDD_GENL_NAME		"mdd"
#define MDD_GENL_VERSION	0x01

enum mdd_nl_commands {
	MDD_NL_CMD_UNSPEC	= 0,

	MDD_NL_CMD_CHANGELOG	= 1,

	__MDD_NL_CMD_MAX_PLUS_ONE
};

#define MDD_NL_CMD_MAX	(__MDD_NL_CMD_MAX_PLUS_ONE - 1)

#define LQUOTA_GENL_NAME	"lquota"
#define LQUOTA_GENL_VERSION	0x01

enum lquota_nl_commands {
	LQUOTA_NL_CMD_UNSPEC	= 0,

	LQUOTA_NL_CMD_QUOTA	= 1,

	__LQUOTA_NL_CMD_MAX_PLUS_ONE
};

#define LQUOTA_NL_CMD_MAX	(__LQUOTA_NL_CMD_MAX_PLUS_ONE - 1)

/* KUC message header.
 * All current and future KUC messages should use this header.
 * To avoid having to include Lustre headers from libcfs, define this here.
 */
struct kuc_hdr {
	__u16 kuc_magic;
	__u8  kuc_transport;  /* Each new Lustre feature should use a different
			       * transport
			       */
	__u8  kuc_flags;
	__u16 kuc_msgtype;    /* Message type or opcode, transport-specific */
	__u16 kuc_msglen;     /* Including header */
} __attribute__((aligned(sizeof(__u64))));


#define KUC_MAGIC  0x191C /*Lustre9etLinC */

/* kuc_msgtype values are defined in each transport */
enum kuc_transport_type {
	KUC_TRANSPORT_GENERIC   = 1,
	KUC_TRANSPORT_HSM       = 2,
};

enum kuc_generic_message_type {
	KUC_MSG_SHUTDOWN = 1,
};

/* KUC Broadcast Groups. This determines which userspace process hears which
 * messages.  Mutliple transports may be used within a group, or multiple
 * groups may use the same transport.  Broadcast
 * groups need not be used if e.g. a UID is specified instead;
 * use group 0 to signify unicast.
 */
#define KUC_GRP_HSM	0x02
#define KUC_GRP_MAX	KUC_GRP_HSM

enum lk_flags {
	LK_FLG_STOP	= 0x0001,
	LK_FLG_DATANR	= 0x0002,
};
#define LK_NOFD -1U

/* kernelcomm control structure, passed from userspace to kernel.
 * For compatibility with old copytools, users who pass ARCHIVE_IDs
 * to kernel using lk_data_count and lk_data should fill lk_flags with
 * LK_FLG_DATANR. Otherwise kernel will take lk_data_count as bitmap of
 * ARCHIVE IDs.
 */
struct lustre_kernelcomm {
	__u32 lk_wfd;
	__u32 lk_rfd;
	__u32 lk_uid;
	__u32 lk_group;
	__u32 lk_data_count;
	__u32 lk_flags;
	__u32 lk_data[];
} __attribute__((packed));

#endif	/* __UAPI_KERNELCOMM_H__ */
