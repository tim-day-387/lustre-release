// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Timothy Day <timday@amazon.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#include "lnetdump.h"
#include "common.h"
#include "compat.h"

#define DEFAULT_STR "NA"
#define BAD_MAGIC "BM"

static const char *portal_names[] = {
	[LNET_RESERVED_PORTAL]		  = "LNET_RESERVED",
	[CONNMGR_REQUEST_PORTAL]	  = "CONNMGR_REQUEST",
	[CONNMGR_REPLY_PORTAL]		  = "CONNMGR_REPLY",
	[OSC_REPLY_PORTAL]		  = "OSC_REPLY",
	[OST_IO_PORTAL]			  = "OST_IO",
	[OST_CREATE_PORTAL]		  = "OST_CREATE",
	[OST_BULK_PORTAL]		  = "OST_BULK",
	[MDC_REPLY_PORTAL]		  = "MDC_REPLY",
	[MDS_REQUEST_PORTAL]		  = "MDS_REQUEST",
	[MDS_IO_PORTAL]		 	  = "MDS_IO",
	[MDS_BULK_PORTAL]		  = "MDS_BULK",
	[LDLM_CB_REQUEST_PORTAL]	  = "LDLM_CB_REQUEST",
	[LDLM_CB_REPLY_PORTAL]		  = "LDLM_CB_REPLY",
	[LDLM_CANCEL_REQUEST_PORTAL]  	  = "LDLM_CANCEL_REQUEST",
	[LDLM_CANCEL_REPLY_PORTAL]	  = "LDLM_CANCEL_REPLY",
	[MDS_READPAGE_PORTAL]		  = "MDS_READPAGE",
	[OUT_PORTAL]			  = "OUT",
	[MGC_REPLY_PORTAL]		  = "MGC_REPLY",
	[MGS_REQUEST_PORTAL]		  = "MGS_REQUEST",
	[MGS_REPLY_PORTAL]		  = "MGS_REPLY",
	[OST_REQUEST_PORTAL]		  = "OST_REQUEST",
	[FLD_REQUEST_PORTAL]		  = "FLD_REQUEST",
	[SEQ_METADATA_PORTAL]		  = "SEQ_METADATA",
	[SEQ_DATA_PORTAL]		  = "SEQ_DATA",
	[SEQ_CONTROLLER_PORTAL]		  = "SEQ_CONTROLLER",
	[MGS_BULK_PORTAL]		  = "MGS_BULK",
	[DVS_PORTAL]			  = "DVS",
};

static inline const char *portal_name(int portal, char *default_str)
{
	if (portal < 0 || portal >= (int)(sizeof(portal_names) / sizeof(portal_names[0])) ||
	    portal_names[portal] == NULL)
		return default_str;

	return portal_names[portal];
}

static const char *type_names[] = {
	[LNET_MSG_ACK]		= "ACK",
	[LNET_MSG_PUT]		= "PUT",
	[LNET_MSG_GET]		= "GET",
	[LNET_MSG_REPLY]	= "REPLY",
	[LNET_MSG_HELLO]	= "HELLO",
};

static inline const char *type_name(int type, char *default_str)
{
	if (type < 0 || type >= (int)(sizeof(type_names) / sizeof(type_names[0])) ||
	    type_names[type] == NULL)
		return default_str;

	return type_names[type];
}

static const char *opcode_names[] = {
	/* OST opcodes */
	[OST_REPLY]      = "OST_REPLY",
	[OST_GETATTR]    = "OST_GETATTR",
	[OST_SETATTR]    = "OST_SETATTR",
	[OST_READ]       = "OST_READ",
	[OST_WRITE]      = "OST_WRITE",
	[OST_CREATE]     = "OST_CREATE",
	[OST_DESTROY]    = "OST_DESTROY",
	[OST_GET_INFO]   = "OST_GET_INFO",
	[OST_CONNECT]    = "OST_CONNECT",
	[OST_DISCONNECT] = "OST_DISCONNECT",
	[OST_PUNCH]      = "OST_PUNCH",
	[OST_OPEN]       = "OST_OPEN",
	[OST_CLOSE]      = "OST_CLOSE",
	[OST_STATFS]     = "OST_STATFS",
	[OST_SYNC]       = "OST_SYNC",
	[OST_SET_INFO]   = "OST_SET_INFO",
	[OST_QUOTACHECK] = "OST_QUOTACHECK",
	[OST_QUOTACTL]   = "OST_QUOTACTL",
	[OST_QUOTA_ADJUST_QUNIT] = "OST_QUOTA_ADJUST_QUNIT",
	[OST_LADVISE]    = "OST_LADVISE",
	[OST_FALLOCATE]  = "OST_FALLOCATE",
	[OST_SEEK]       = "OST_SEEK",

	/* MDS opcodes */
	[MDS_GETATTR]           = "MDS_GETATTR",
	[MDS_GETATTR_NAME]      = "MDS_GETATTR_NAME",
	[MDS_CLOSE]             = "MDS_CLOSE",
	[MDS_REINT]             = "MDS_REINT",
	[MDS_READPAGE]          = "MDS_READPAGE",
	[MDS_CONNECT]           = "MDS_CONNECT",
	[MDS_DISCONNECT]        = "MDS_DISCONNECT",
	[MDS_GET_ROOT]          = "MDS_GET_ROOT",
	[MDS_STATFS]            = "MDS_STATFS",
	[MDS_PIN]               = "MDS_PIN",
	[MDS_UNPIN]             = "MDS_UNPIN",
	[MDS_SYNC]              = "MDS_SYNC",
	[MDS_DONE_WRITING]      = "MDS_DONE_WRITING",
	[MDS_SET_INFO]          = "MDS_SET_INFO",
	[MDS_QUOTACHECK]        = "MDS_QUOTACHECK",
	[MDS_QUOTACTL]          = "MDS_QUOTACTL",
	[MDS_GETXATTR]          = "MDS_GETXATTR",
	[MDS_SETXATTR]          = "MDS_SETXATTR",
	[MDS_WRITEPAGE]         = "MDS_WRITEPAGE",
	[MDS_IS_SUBDIR]         = "MDS_IS_SUBDIR",
	[MDS_GET_INFO]          = "MDS_GET_INFO",
	[MDS_HSM_STATE_GET]     = "MDS_HSM_STATE_GET",
	[MDS_HSM_STATE_SET]     = "MDS_HSM_STATE_SET",
	[MDS_HSM_ACTION]        = "MDS_HSM_ACTION",
	[MDS_HSM_PROGRESS]      = "MDS_HSM_PROGRESS",
	[MDS_HSM_REQUEST]       = "MDS_HSM_REQUEST",
	[MDS_HSM_CT_REGISTER]   = "MDS_HSM_CT_REGISTER",
	[MDS_HSM_CT_UNREGISTER] = "MDS_HSM_CT_UNREGISTER",
	[MDS_SWAP_LAYOUTS]      = "MDS_SWAP_LAYOUTS",
	[MDS_RMFID]             = "MDS_RMFID",
	[MDS_BATCH]             = "MDS_BATCH",
	[MDS_HSM_DATA_VERSION]  = "MDS_HSM_DATA_VERSION",

	/* SEQ opcodes */
	[SEQ_QUERY]     = "SEQ_QUERY",

	/* FLD opcodes */
	[FLD_QUERY]     = "FLD_QUERY",
	[FLD_READ]      = "FLD_READ",

	/* LFSCK opcodes */
	[LFSCK_NOTIFY]   = "LFSCK_NOTIFY",
	[LFSCK_QUERY]    = "LFSCK_QUERY",

	/* MGS opcodes */
	[MGS_CONNECT]     = "MGS_CONNECT",
	[MGS_DISCONNECT]  = "MGS_DISCONNECT",
	[MGS_EXCEPTION]   = "MGS_EXCEPTION",
	[MGS_TARGET_REG]  = "MGS_TARGET_REG",
	[MGS_TARGET_DEL]  = "MGS_TARGET_DEL",
	[MGS_SET_INFO]    = "MGS_SET_INFO",
	[MGS_CONFIG_READ] = "MGS_CONFIG_READ",

	/* OBD opcodes */
	[OBD_PING]        = "OBD_PING",
	[OBD_IDX_READ]    = "OBD_IDX_READ",

	/* LLOG opcodes */
	[LLOG_ORIGIN_HANDLE_CREATE]      = "LLOG_ORIGIN_HANDLE_CREATE",
	[LLOG_ORIGIN_HANDLE_NEXT_BLOCK]  = "LLOG_ORIGIN_HANDLE_NEXT_BLOCK",
	[LLOG_ORIGIN_HANDLE_READ_HEADER] = "LLOG_ORIGIN_HANDLE_READ_HEADER",
	[LLOG_ORIGIN_HANDLE_PREV_BLOCK]  = "LLOG_ORIGIN_HANDLE_PREV_BLOCK",
	[LLOG_ORIGIN_HANDLE_DESTROY]     = "LLOG_ORIGIN_HANDLE_DESTROY",

	/* LDLM opcodes */
	[LDLM_ENQUEUE]     = "LDLM_ENQUEUE",
	[LDLM_CONVERT]     = "LDLM_CONVERT",
	[LDLM_CANCEL]      = "LDLM_CANCEL",
	[LDLM_BL_CALLBACK] = "LDLM_BL_CALLBACK",
	[LDLM_CP_CALLBACK] = "LDLM_CP_CALLBACK",
	[LDLM_GL_CALLBACK] = "LDLM_GL_CALLBACK",
	[LDLM_SET_INFO]    = "LDLM_SET_INFO",
};

static inline const char *opc_name(int opc, char *default_str)
{
	if (opc < 0 || opc >= (int)(sizeof(opcode_names) / sizeof(opcode_names[0])) ||
	    opcode_names[opc] == NULL)
		return default_str;

	return opcode_names[opc];
}

static char print_fmt[256] = "%-5c %Lm %-5Ls %-5Lt %-20LP [%-16Pj] %-30Po %Dt %Dc %Dn";

static int expand_code_single(const char *code, const struct data_t *ev,
			      char *buf, size_t size)
{
	static unsigned int count = 0;

	switch (code[0]) {
	case 'c':
		return snprintf(buf, size, "%u", count++);
	default:
		return snprintf(buf, size, "%%%c", code[0]);
	}
}

static int expand_code_ptlrpc(const char *code, const struct data_t *ev,
			      char *buf, size_t size)
{
	struct lustre_msg_v2 *msg_body = (struct lustre_msg_v2 *)&ev->msg_payload;
	void *end = (void *)&ev->msg_payload + PAYLOAD_SIZE;
	struct ptlrpc_body_v3 *ptlrpc_body = NULL;
	void *start = (void *)&ev->msg_payload;
	const char *msg_portal_name = NULL;
	const char *msg_opc_name = NULL;
	bool valid_ptlrpc_body = false;
	const char *msg_job_id = NULL;
	__u32 projid = 0;
	__u32 limit = 0;
	__u32 uid = 0;
	__u32 gid = 0;
	__u64 slv = 0;
	int rc = 0;

	msg_portal_name = portal_name(ev->msg_ptl, NULL);

	if (msg_portal_name && ev->msg_ptl != LNET_RESERVED_PORTAL) {
		ptlrpc_body = lustre_msg_ptlrpc_body(msg_body);
		if (bound_check(ptlrpc_body, start, end))
			valid_ptlrpc_body = true;
	}

	if (!valid_ptlrpc_body)
		return snprintf(buf, size, DEFAULT_STR);

	switch (code[1]) {
	case 'o':
		msg_opc_name = opc_name(ptlrpc_body->pb_opc, NULL);

		if (msg_opc_name)
			return snprintf(buf, size, "%s", msg_opc_name);
		else
			return snprintf(buf, size, "%u", ptlrpc_body->pb_opc);
	case 'j':
		msg_job_id = lustre_msg_get_jobid(msg_body);
		if (!msg_job_id)
			return snprintf(buf, size, DEFAULT_STR);

		rc = snprintf(buf, size, "%s", msg_job_id);
		if (!rc)
			return snprintf(buf, size, "EMPTY");

		return rc;
	case 'u':
		rc = lustre_msg_get_uid_gid(msg_body, &uid, NULL);
		if (rc)
			return snprintf(buf, size, DEFAULT_STR);

		return snprintf(buf, size, "%u", uid);
	case 'g':
		rc = lustre_msg_get_uid_gid(msg_body, NULL, &gid);
		if (rc)
			return snprintf(buf, size, DEFAULT_STR);

		return snprintf(buf, size, "%u", gid);
	case 'p':
		rc = lustre_msg_get_projid(msg_body, &projid);
		if (rc)
			return snprintf(buf, size, DEFAULT_STR);

		return snprintf(buf, size, "%u", projid);
	case 'L':
		limit = lustre_msg_get_limit(msg_body);
		if (limit < 0)
			return snprintf(buf, size, DEFAULT_STR);

		return snprintf(buf, size, "%u", limit);
	case 'S':
		slv = lustre_msg_get_slv(msg_body);
		if (slv < 0)
			return snprintf(buf, size, DEFAULT_STR);

		return snprintf(buf, size, "%llu", slv);
	default:
		return snprintf(buf, size, "%%%c", code[0]);
	}
}

/*
 * Extract FID from LDLM resource. Reverse of fid_build_reg_res_name().
 */
static inline void
fid_extract_from_res_name(struct lu_fid *fid, const struct ldlm_res_id *res)
{
	fid->f_seq = res->name[LUSTRE_RES_ID_SEQ_OFF];
	fid->f_oid = (__u32)(res->name[LUSTRE_RES_ID_VER_OID_OFF]);
	fid->f_ver = (__u32)(res->name[LUSTRE_RES_ID_VER_OID_OFF] >> 32);
}

void lustre_swab_ldlm_res_id(struct ldlm_res_id *id)
{
	int i;

	for (i = 0; i < RES_NAME_SIZE; i++)
		__swab64s(&id->name[i]);
}

static int expand_code_ldlm(const char *code, const struct data_t *ev,
			    char *buf, size_t size)
{
	struct lustre_msg_v2 *msg_body = (struct lustre_msg_v2 *)&ev->msg_payload;
	void *end = (void *)&ev->msg_payload + PAYLOAD_SIZE;
	struct ptlrpc_body_v3 *ptlrpc_body = NULL;
	void *start = (void *)&ev->msg_payload;
	const char *msg_portal_name = NULL;
	const char *msg_opc_name = NULL;
	struct ldlm_request *dlm = NULL;
	bool valid_ptlrpc_body = false;
	const char *msg_job_id = NULL;
	struct ldlm_res_id res_id;
	struct lu_fid fid;
	__u32 projid = 0;
	__u32 limit = 0;
	__u32 uid = 0;
	__u32 gid = 0;
	__u64 slv = 0;
	int rc = 0;

	struct req_capsule pill = {
	    .rc_reqmsg = msg_body,
	    .rc_repmsg = msg_body,
	    .rc_fmt = &RQF_LDLM_ENQUEUE,
	    .rc_loc = RCL_CLIENT,
	};

	msg_portal_name = portal_name(ev->msg_ptl, NULL);

	if (msg_portal_name && ev->msg_ptl != LNET_RESERVED_PORTAL) {
		ptlrpc_body = lustre_msg_ptlrpc_body(msg_body);
		if (bound_check(ptlrpc_body, start, end))
			valid_ptlrpc_body = true;
	}

	if (!valid_ptlrpc_body)
		return snprintf(buf, size, "no_ptlrpc");

	req_capsule_init_area(&pill);
	req_capsule_filled_sizes(&pill, RCL_CLIENT);

	dlm = req_capsule_client_get(&pill, &RMF_DLM_REQ);
	if (!dlm || ptlrpc_body->pb_opc != LDLM_ENQUEUE)
		return snprintf(buf, size, "no_dlm");

	switch (code[1]) {
	case 'c':
		return snprintf(buf, size, "%u", dlm->lock_count);
	case 't':
		return snprintf(buf, size, "%u", dlm->lock_desc.l_resource.lr_type);
	case 'n':
	  /*
		return snprintf(buf, size, "%llu:%llu:%llu:%llu",
				dlm->lock_desc.l_resource.lr_name.name[0],
				dlm->lock_desc.l_resource.lr_name.name[1],
				dlm->lock_desc.l_resource.lr_name.name[2],
				dlm->lock_desc.l_resource.lr_name.name[3]);
	  */
		res_id = dlm->lock_desc.l_resource.lr_name;
		// lustre_swab_ldlm_res_id(&res_id);
		fid_extract_from_res_name(&fid, &res_id);
		return snprintf(buf, size, DFID, PFID(&fid));
	default:
		return snprintf(buf, size, "%%%c", code[0]);
	}
}

static int expand_code_lnet(const char *code, const struct data_t *ev,
			    char *buf, size_t size)
{
	const char *msg_send_or_recv = NULL;
	const char *msg_portal_name = NULL;
	__u64 mbits = 0;

	msg_portal_name = portal_name(ev->msg_ptl, NULL);

	switch (code[1]) {
	case 's':
		if (ev->send_or_recv == 0)
			msg_send_or_recv = "SEND";
		else if (ev->send_or_recv == 1)
			msg_send_or_recv = "RECV";
		else
			msg_send_or_recv = "UNKNOWN";

		return snprintf(buf, size, "%s", msg_send_or_recv);
	case 't':
		return snprintf(buf, size, "%s", type_name(ev->msg_type, DEFAULT_STR));
	case 'l':
		return snprintf(buf, size, "%u", ev->msg_len);
	case 'P':
		return snprintf(buf, size, "%s", portal_name(ev->msg_ptl, DEFAULT_STR));
	case 'm':
		/* TODO: We could get this directly from
		 * lustre_msg_get_mbits(), but getting it
		 * from LNet results seemingly more correct
		 * results. I don't understand why...
		 */
		mbits = ev->msg_mbits;

		return snprintf(buf, size, "0x%llX", mbits);
	default:
		return snprintf(buf, size, "%%%c", code[0]);
	}
}

static int expand_code(const char *code, const struct data_t *ev,
		       char *buf, size_t size)
{
	int len = strlen(code);
	int rc = 0;

	if (len <= 0 || len > 2)
		return snprintf(buf, size, "%%%s", code);

	if (strlen(code) == 1)
		return expand_code_single(code, ev, buf, size);

	switch (code[0]) {
	case 'L':
		rc = expand_code_lnet(code, ev, buf, size);
		if (rc)
			return rc;
	case 'D':
		rc = expand_code_ldlm(code, ev, buf, size);
		if (rc)
			return rc;
	case 'P':
		rc = expand_code_ptlrpc(code, ev, buf, size);
		if (rc)
			return rc;
	default:
		return expand_code_single(code, ev, buf, size);
	}
}

static int pretty_expand(const char *fmt, const struct data_t *ev,
			 char *out, size_t size)
{
	size_t outlen = 0;

	while (*fmt) {
		if (*fmt == '%' && *(fmt+1)) {
			int left_align = 0;
			int width = 0;

			fmt++;

			// Handle optional '-'
			if (*fmt == '-') {
				left_align = 1;
				fmt++;
			}

			// Parse width digits
			while (*fmt >= '0' && *fmt <= '9') {
				width = width * 10 + (*fmt - '0');
				fmt++;
			}

			char code[3] = {0};
			int code_len = 0;

			// Extract format code (try two characters first, then fallback to single)
			if (*fmt) {
				code[code_len++] = *fmt++;
				// Try two-character code if there's a next character
				if (*fmt) {
					code[code_len++] = *fmt;
					// Test if two-character code is valid
					char test_buf[256];
					if (expand_code(code, ev, test_buf, sizeof(test_buf)) >= 0 &&
					    strncmp(test_buf, "%", 1) != 0) {
						// Two-character code is valid, consume the second character
						fmt++;
					} else {
						// Two-character code not valid, use only first character
						code[1] = '\0';
						code_len = 1;
					}
				}
			}

			char tmp[256];
			int n = expand_code(code, ev, tmp, sizeof(tmp));

			if (n < 0)
				return -1;

			int pad = (width > n) ? (width - n) : 0;

			if (outlen + n + pad + 1 > size)
				return -1;

			if (!left_align) {
				// right align -> pad first
				memset(out + outlen, ' ', pad);
				outlen += pad;
			}

			memcpy(out + outlen, tmp, n);
			outlen += n;

			if (left_align) {
				// left align -> pad after
				memset(out + outlen, ' ', pad);
				outlen += pad;
			}

			continue;
		}

		if (outlen + 2 > size)
			return -1;

		out[outlen++] = *fmt++;
	}

	out[outlen] = '\0';

	return 0;
}

static int print_output_parse_args(int c, char *optarg)
{
	switch (c) {
	case 'p':
		strcpy(print_fmt, optarg);
		return 0;
	default:
		return -1;
	}
}

static void print_output_handle_event(void *ctx, int cpu,
				      void *data, __u32 data_sz)
{
	const struct data_t *ev = data;
	char out[256];

	pretty_expand(print_fmt, ev, out, 256);

	printf("%s\n", out);
}

static void print_output_lost_event(void *ctx, int cpu, __u64 cnt)
{
	fprintf(stderr, "Lost %llu events on CPU %d\n", (unsigned long long)cnt, cpu);
}

const struct lnetdump_output_methods print_output_methods = {
	.lom_parse_args = print_output_parse_args,
	.lom_sample_cb = print_output_handle_event,
	.lom_lost_cb = print_output_lost_event,
};
