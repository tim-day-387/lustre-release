/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Code shared between userspace components.
 *
 * Author: Timothy Day <timday@amazon.com>
 */

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <linux/lustre/lustre_idl.h>

/* Global Definitions */

#define VERSION_STRING "0.1.2"

/* Misc */

typedef int (*lom_parse_args_fn)(int c, char *optarg);

struct lnetdump_output_methods {
	lom_parse_args_fn	lom_parse_args;
	perf_buffer_sample_fn	lom_sample_cb;
	perf_buffer_lost_fn	lom_lost_cb;
};

typedef int (*lnetdump_input_fn)(const struct lnetdump_output_methods *lom);

/* lnetdump.c */

extern volatile bool exiting;

/* pack.c */

struct ptlrpc_body *lustre_msg_ptlrpc_body(struct lustre_msg *msg);
char *lustre_msg_get_jobid(struct lustre_msg *msg);
int lustre_msg_get_projid(struct lustre_msg *msg, __u32 *projid);
int lustre_msg_get_uid_gid(struct lustre_msg *msg, __u32 *uid, __u32 *gid);
__u32 lustre_msg_get_limit(struct lustre_msg *msg);
__u64 lustre_msg_get_slv(struct lustre_msg *msg);
__u32 lustre_msg_size(__u32 magic, int count, __u32 *lens);
void *lustre_msg_buf(struct lustre_msg *m, __u32 n, __u32 min_size);
__u32 lustre_msg_buflen(struct lustre_msg *m, __u32 n);
__u32 lustre_msg_bufcount(struct lustre_msg *m);
__u32 lustre_msg_hdr_size(__u32 magic, __u32 count);
__u32 lustre_msg_size_v2(int count, __u32 *lengths);
int lustre_shrink_msg(struct lustre_msg *msg, int segment,
		      unsigned int newlen, int move_data);
char *lustre_msg_string(struct lustre_msg *m, __u32 index, __u32 max_len);

static bool bound_check(void *input, void *start, void *end)
{
	if (input && input >= start && input < end)
		return true;
	else
		return false;
}

/* layout.c */

enum req_location {
	RCL_CLIENT,
	RCL_SERVER,
	RCL_NR
};

/* Maximal number of fields (buffers) in a request message. */
#define REQ_MAX_FIELD_NR 12

struct req_capsule {
	/* Request message - what client sent */
	struct lustre_msg	*rc_reqmsg;
	/* Reply message - server response */
	struct lustre_msg	*rc_repmsg;
	/* Fields that help to see if request and reply were swabved or not */
	__u32			 rc_req_swab_mask;
	__u32			 rc_rep_swab_mask;
	const struct req_format *rc_fmt;
	enum req_location	 rc_loc;
	__u32			 rc_area[RCL_NR][REQ_MAX_FIELD_NR];
};

struct req_msg_field;

void *req_capsule_client_get(struct req_capsule *pill,
			     const struct req_msg_field *field);
size_t req_capsule_filled_sizes(struct req_capsule *pill,
				enum req_location loc);
void req_capsule_init_area(struct req_capsule *pill);
int req_layout_init(void);

extern struct req_format RQF_OBD_PING;
extern struct req_format RQF_OBD_SET_INFO;
extern struct req_format RQF_MDT_SET_INFO;
extern struct req_format RQF_SEC_CTX;
extern struct req_format RQF_OBD_IDX_READ;
/* MGS req_format */
extern struct req_format RQF_MGS_TARGET_REG;
extern struct req_format RQF_MGS_TARGET_REG_NIDLIST;
extern struct req_format RQF_MGS_SET_INFO;
extern struct req_format RQF_MGS_CONFIG_READ;
/* fid/fld req_format */
extern struct req_format RQF_SEQ_QUERY;
extern struct req_format RQF_FLD_QUERY;
extern struct req_format RQF_FLD_READ;
/* MDS req_format */
extern struct req_format RQF_MDS_CONNECT;
extern struct req_format RQF_MDS_DISCONNECT;
extern struct req_format RQF_MDS_STATFS;
extern struct req_format RQF_MDS_STATFS_NEW;
extern struct req_format RQF_MDS_GET_ROOT;
extern struct req_format RQF_MDS_SYNC;
extern struct req_format RQF_MDS_GETXATTR;
extern struct req_format RQF_MDS_GETATTR;
extern struct req_format RQF_OUT_UPDATE;

/*
 * This is format of direct (non-intent) MDS_GETATTR_NAME request.
 */
extern struct req_format RQF_MDS_GETATTR_NAME;
extern struct req_format RQF_MDS_CLOSE;
extern struct req_format RQF_MDS_CLOSE_INTENT;
extern struct req_format RQF_MDS_CONNECT;
extern struct req_format RQF_MDS_DISCONNECT;
extern struct req_format RQF_MDS_GET_INFO;
extern struct req_format RQF_MDS_FID2PATH;
extern struct req_format RQF_MDS_READPAGE;
extern struct req_format RQF_MDS_REINT;
extern struct req_format RQF_MDS_REINT_CREATE;
extern struct req_format RQF_MDS_REINT_CREATE_ACL;
extern struct req_format RQF_MDS_REINT_CREATE_SLAVE;
extern struct req_format RQF_MDS_REINT_CREATE_SYM;
extern struct req_format RQF_MDS_REINT_OPEN;
extern struct req_format RQF_MDS_REINT_UNLINK;
extern struct req_format RQF_MDS_REINT_LINK;
extern struct req_format RQF_MDS_REINT_RENAME;
extern struct req_format RQF_MDS_REINT_SETATTR;
extern struct req_format RQF_MDS_REINT_SETXATTR;
extern struct req_format RQF_MDS_QUOTACTL;
extern struct req_format RQF_QUOTA_DQACQ;
extern struct req_format RQF_MDS_SWAP_LAYOUTS;
extern struct req_format RQF_MDS_REINT_MIGRATE;
extern struct req_format RQF_MDS_REINT_RESYNC;
extern struct req_format RQF_MDS_RMFID;
/* MDS hsm formats */
extern struct req_format RQF_MDS_HSM_STATE_GET;
extern struct req_format RQF_MDS_HSM_STATE_SET;
extern struct req_format RQF_MDS_HSM_ACTION;
extern struct req_format RQF_MDS_HSM_PROGRESS;
extern struct req_format RQF_MDS_HSM_CT_REGISTER;
extern struct req_format RQF_MDS_HSM_CT_UNREGISTER;
extern struct req_format RQF_MDS_HSM_REQUEST;
extern struct req_format RQF_MDS_HSM_DATA_VERSION;
/* OST req_format */
extern struct req_format RQF_OST_CONNECT;
extern struct req_format RQF_OST_DISCONNECT;
extern struct req_format RQF_OST_QUOTACTL;
extern struct req_format RQF_OST_GETATTR;
extern struct req_format RQF_OST_SETATTR;
extern struct req_format RQF_OST_CREATE;
extern struct req_format RQF_OST_PUNCH;
extern struct req_format RQF_OST_FALLOCATE;
extern struct req_format RQF_OST_SYNC;
extern struct req_format RQF_OST_DESTROY;
extern struct req_format RQF_OST_BRW_READ;
extern struct req_format RQF_OST_BRW_WRITE;
extern struct req_format RQF_OST_STATFS;
extern struct req_format RQF_OST_SET_GRANT_INFO;
extern struct req_format RQF_OST_GET_INFO;
extern struct req_format RQF_OST_GET_INFO_LAST_ID;
extern struct req_format RQF_OST_GET_INFO_LAST_FID;
extern struct req_format RQF_OST_SET_INFO_LAST_FID;
extern struct req_format RQF_OST_GET_INFO_FIEMAP;
extern struct req_format RQF_OST_LADVISE;
extern struct req_format RQF_OST_SEEK;

/* LDLM req_format */
extern struct req_format RQF_LDLM_ENQUEUE;
extern struct req_format RQF_LDLM_ENQUEUE_LVB;
extern struct req_format RQF_LDLM_CONVERT;
extern struct req_format RQF_LDLM_INTENT;
extern struct req_format RQF_LDLM_INTENT_BASIC;
extern struct req_format RQF_LDLM_INTENT_LAYOUT;
extern struct req_format RQF_LDLM_INTENT_GETATTR;
extern struct req_format RQF_LDLM_INTENT_OPEN;
extern struct req_format RQF_LDLM_INTENT_CREATE;
extern struct req_format RQF_LDLM_INTENT_GETXATTR;
extern struct req_format RQF_LDLM_INTENT_QUOTA;
extern struct req_format RQF_LDLM_CANCEL;
extern struct req_format RQF_LDLM_CALLBACK;
extern struct req_format RQF_LDLM_CP_CALLBACK;
extern struct req_format RQF_LDLM_BL_CALLBACK;
extern struct req_format RQF_LDLM_GL_CALLBACK;
extern struct req_format RQF_LDLM_GL_CALLBACK_DESC;
/* LOG req_format */
extern struct req_format RQF_LLOG_ORIGIN_HANDLE_CREATE;
extern struct req_format RQF_LLOG_ORIGIN_HANDLE_NEXT_BLOCK;
extern struct req_format RQF_LLOG_ORIGIN_HANDLE_PREV_BLOCK;
extern struct req_format RQF_LLOG_ORIGIN_HANDLE_READ_HEADER;

extern struct req_format RQF_CONNECT;

/* LFSCK req_format */
extern struct req_format RQF_LFSCK_NOTIFY;
extern struct req_format RQF_LFSCK_QUERY;

/* Batch UpdaTe req_format */
extern struct req_format RQF_BUT_GETATTR;
extern struct req_format RQF_MDS_BATCH;

extern struct req_msg_field RMF_GENERIC_DATA;
extern struct req_msg_field RMF_PTLRPC_BODY;
extern struct req_msg_field RMF_MDT_BODY;
extern struct req_msg_field RMF_MDT_EPOCH;
extern struct req_msg_field RMF_OBD_STATFS;
extern struct req_msg_field RMF_NAME;
extern struct req_msg_field RMF_SYMTGT;
extern struct req_msg_field RMF_TGTUUID;
extern struct req_msg_field RMF_CLUUID;
extern struct req_msg_field RMF_SETINFO_VAL;
extern struct req_msg_field RMF_SETINFO_KEY;
extern struct req_msg_field RMF_GETINFO_VAL;
extern struct req_msg_field RMF_GETINFO_VALLEN;
extern struct req_msg_field RMF_GETINFO_KEY;
extern struct req_msg_field RMF_IDX_INFO;
extern struct req_msg_field RMF_CLOSE_DATA;
extern struct req_msg_field RMF_FILE_SECCTX_NAME;
extern struct req_msg_field RMF_FILE_SECCTX;
extern struct req_msg_field RMF_FID_ARRAY;
extern struct req_msg_field RMF_FILE_ENCCTX;

/*
 * connection handle received in MDS_CONNECT request.
 */
extern struct req_msg_field RMF_CONN;
extern struct req_msg_field RMF_CONNECT_DATA;
extern struct req_msg_field RMF_DLM_REQ;
extern struct req_msg_field RMF_DLM_REP;
extern struct req_msg_field RMF_DLM_LVB;
extern struct req_msg_field RMF_DLM_GL_DESC;
extern struct req_msg_field RMF_LDLM_INTENT;
extern struct req_msg_field RMF_LAYOUT_INTENT;
extern struct req_msg_field RMF_MDT_MD;
extern struct req_msg_field RMF_DEFAULT_MDT_MD;
extern struct req_msg_field RMF_REC_REINT;
extern struct req_msg_field RMF_EADATA;
extern struct req_msg_field RMF_EAVALS;
extern struct req_msg_field RMF_EAVALS_LENS;
extern struct req_msg_field RMF_ACL;
extern struct req_msg_field RMF_LOGCOOKIES;
extern struct req_msg_field RMF_CAPA1;
extern struct req_msg_field RMF_CAPA2;
extern struct req_msg_field RMF_OBD_QUOTACHECK;
extern struct req_msg_field RMF_OBD_QUOTACTL;
extern struct req_msg_field RMF_OBD_QUOTA_ITER;
extern struct req_msg_field RMF_OBD_QUOTACTL_POOL;
extern struct req_msg_field RMF_QUOTA_BODY;
extern struct req_msg_field RMF_STRING;
extern struct req_msg_field RMF_SWAP_LAYOUTS;
extern struct req_msg_field RMF_MDS_HSM_PROGRESS;
extern struct req_msg_field RMF_MDS_HSM_REQUEST;
extern struct req_msg_field RMF_MDS_HSM_USER_ITEM;
extern struct req_msg_field RMF_MDS_HSM_ARCHIVE;
extern struct req_msg_field RMF_HSM_USER_STATE;
extern struct req_msg_field RMF_HSM_STATE_SET;
extern struct req_msg_field RMF_MDS_HSM_CURRENT_ACTION;
extern struct req_msg_field RMF_MDS_HSM_REQUEST;
extern struct req_msg_field RMF_SELINUX_POL;

/* seq-mgr fields */
extern struct req_msg_field RMF_SEQ_OPC;
extern struct req_msg_field RMF_SEQ_RANGE;
extern struct req_msg_field RMF_FID_SPACE;

/* FLD fields */
extern struct req_msg_field RMF_FLD_OPC;
extern struct req_msg_field RMF_FLD_MDFLD;

extern struct req_msg_field RMF_LLOGD_BODY;
extern struct req_msg_field RMF_LLOG_LOG_HDR;
extern struct req_msg_field RMF_LLOGD_CONN_BODY;

extern struct req_msg_field RMF_MGS_TARGET_INFO;
extern struct req_msg_field RMF_MGS_TARGET_NIDLIST;
extern struct req_msg_field RMF_MGS_SEND_PARAM;

extern struct req_msg_field RMF_OST_BODY;
extern struct req_msg_field RMF_OBD_IOOBJ;
extern struct req_msg_field RMF_OBD_ID;
extern struct req_msg_field RMF_FID;
extern struct req_msg_field RMF_NIOBUF_REMOTE;
extern struct req_msg_field RMF_NIOBUF_INLINE;
extern struct req_msg_field RMF_RCS;
extern struct req_msg_field RMF_FIEMAP_KEY;
extern struct req_msg_field RMF_FIEMAP_VAL;
extern struct req_msg_field RMF_OST_ID;
extern struct req_msg_field RMF_SHORT_IO;

/* MGS config read message format */
extern struct req_msg_field RMF_MGS_CONFIG_BODY;
extern struct req_msg_field RMF_MGS_CONFIG_RES;

/* generic uint32 */
extern struct req_msg_field RMF_U32;

/* OBJ update format */
extern struct req_msg_field RMF_OUT_UPDATE;
extern struct req_msg_field RMF_OUT_UPDATE_REPLY;
extern struct req_msg_field RMF_OUT_UPDATE_HEADER;
extern struct req_msg_field RMF_OUT_UPDATE_BUF;

/* Batch UpdaTe format */
extern struct req_msg_field RMF_BUT_REPLY;
extern struct req_msg_field RMF_BUT_HEADER;
extern struct req_msg_field RMF_BUT_BUF;

/* LFSCK format */
extern struct req_msg_field RMF_LFSCK_REQUEST;
extern struct req_msg_field RMF_LFSCK_REPLY;

extern struct req_msg_field RMF_OST_LADVISE_HDR;
extern struct req_msg_field RMF_OST_LADVISE;

/* bpf_input.c */

int lnetdump_bpf_input(const struct lnetdump_output_methods *lom);

/* print_output.c */

extern const struct lnetdump_output_methods print_output_methods;
