// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * (Un)packing of Lustre requests. The code has been modified
 * to better support eBPF/lnetdump.
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Eric Barton <eeb@clusterfs.com>
 * Modified for Userspace: Timothy Day <timday@amazon.com>
 */

#include <linux/lustre/lustre_idl.h>

#include "lnetdump.h"
#include "compat.h"

/* TODO: These numbers are made up... */
#define PTLRPC_MAX_BUFCOUNT (256 * 2)
#define PTLRPC_MAX_BUFLEN (4096 * 2)

static inline __u32 lustre_msg_hdr_size_v2(__u32 count)
{
	return round_up(offsetof(struct lustre_msg_v2, lm_buflens[count]), 8);
}

__u32 lustre_msg_hdr_size(__u32 magic, __u32 count)
{
	switch (magic) {
	case LUSTRE_MSG_MAGIC_V2:
		return lustre_msg_hdr_size_v2(count);
	default:
		return 0;
	}
}

enum lustre_msg_version lustre_msg_get_version(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL) {
			return 0;
		}
		return pb->pb_version;
	}
	default:
		return 0;
	}
}

static inline int lustre_msg_check_version_v2(struct lustre_msg_v2 *msg,
					      enum lustre_msg_version version)
{
	enum lustre_msg_version ver = lustre_msg_get_version(msg);

	return (ver & LUSTRE_VERSION_MASK) != version;
}

int lustre_msg_check_version(struct lustre_msg *msg,
			     enum lustre_msg_version version)
{
#define LUSTRE_MSG_MAGIC_V1 0x0BD00BD0
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V1:
		return -EINVAL;
	case LUSTRE_MSG_MAGIC_V2:
		return lustre_msg_check_version_v2(msg, version);
	default:
		return -EPROTO;
	}
#undef LUSTRE_MSG_MAGIC_V1
}

__u32 lustre_msg_early_size;

/* early reply size */
void lustre_msg_early_size_init(void)
{
	__u32 pblen = sizeof(struct ptlrpc_body);

	lustre_msg_early_size = lustre_msg_size(LUSTRE_MSG_MAGIC_V2, 1, &pblen);
}

__u32 lustre_msg_size_v2(int count, __u32 *lengths)
{
	__u32 size;
	int i;

	size = lustre_msg_hdr_size_v2(count);
	for (i = 0; i < count; i++)
		size += round_up(lengths[i], 8);

	return size;
}

/*
 * This returns the size of the buffer that is required to hold a lustre_msg
 * with the given sub-buffer lengths.
 * NOTE: this should only be used for NEW requests, and should always be
 *       in the form of a v2 request.  If this is a connection to a v1
 *       target then the first buffer will be stripped because the ptlrpc
 *       data is part of the lustre_msg_v1 header. b=14043
 */
__u32 lustre_msg_size(__u32 magic, int count, __u32 *lens)
{
	__u32 size[] = { sizeof(struct ptlrpc_body) };

	if (!lens)
		lens = size;

	switch (magic) {
	case LUSTRE_MSG_MAGIC_V2:
		return lustre_msg_size_v2(count, lens);
	default:
		return 0;
	}
}

/*
 * This is used to determine the size of a buffer that was already packed
 * and will correctly handle the different message formats.
 */
__u32 lustre_packed_msg_size(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		return lustre_msg_size_v2(msg->lm_bufcount, msg->lm_buflens);
	default:
		return 0;
	}
}

void lustre_init_msg_v2(struct lustre_msg_v2 *msg, int count, __u32 *lens,
			char **bufs)
{
	char *ptr;
	int i;

	msg->lm_bufcount = count;
	/* XXX: lm_secflvr uninitialized here */
	msg->lm_magic = LUSTRE_MSG_MAGIC_V2;

	for (i = 0; i < count; i++)
		msg->lm_buflens[i] = lens[i];

	if (bufs == NULL)
		return;

	ptr = (char *)msg + lustre_msg_hdr_size_v2(count);
	for (i = 0; i < count; i++) {
		char *tmp = bufs[i];

		if (tmp)
			memcpy(ptr, tmp, lens[i]);
		ptr += round_up(lens[i], 8);
	}
}

void *lustre_msg_buf_v2(struct lustre_msg_v2 *m, __u32 n, __u32 min_size)
{
	__u32 i, offset, buflen, bufcount;

	bufcount = m->lm_bufcount;
	if (!m || bufcount <= 0)
		return NULL;

	if (n >= bufcount)
		return NULL;

	buflen = m->lm_buflens[n];
	if (buflen < min_size)
		return NULL;

	offset = lustre_msg_hdr_size_v2(bufcount);
	for (i = 0; i < n; i++)
		offset += round_up(m->lm_buflens[i], 8);

	return (char *)m + offset;
}

void *lustre_msg_buf(struct lustre_msg *m, __u32 n, __u32 min_size)
{
	switch (m->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		return lustre_msg_buf_v2(m, n, min_size);
	default:
		return NULL;
	}
}

static int lustre_shrink_msg_v2(struct lustre_msg_v2 *msg, __u32 segment,
				unsigned int newlen, int move_data)
{
	char *tail = NULL, *newpos;
	int tail_len = 0, n;

	if (msg->lm_buflens[segment] == newlen)
		goto out;

	if (move_data && msg->lm_bufcount > segment + 1) {
		tail = lustre_msg_buf_v2(msg, segment + 1, 0);
		for (n = segment + 1; n < msg->lm_bufcount; n++)
			tail_len += round_up(msg->lm_buflens[n], 8);
	}

	msg->lm_buflens[segment] = newlen;

	if (tail && tail_len) {
		newpos = lustre_msg_buf_v2(msg, segment + 1, 0);
		if (newpos != tail)
			memmove(newpos, tail, tail_len);
	}
out:
	return lustre_msg_size_v2(msg->lm_bufcount, msg->lm_buflens);
}

/*
 * for @msg, shrink @segment to size @newlen. if @move_data is non-zero,
 * we also move data forward from @segment + 1.
 *
 * if @newlen == 0, we remove the segment completely, but we still keep the
 * totally bufcount the same to save possible data moving. this will leave a
 * unused segment with size 0 at the tail, but that's ok.
 *
 * return new msg size after shrinking.
 *
 * CAUTION:
 * + if any buffers higher than @segment has been filled in, must call shrink
 *   with non-zero @move_data.
 * + caller should NOT keep pointers to msg buffers which higher than @segment
 *   after call shrink.
 */
int lustre_shrink_msg(struct lustre_msg *msg, int segment,
		      unsigned int newlen, int move_data)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		return lustre_shrink_msg_v2(msg, segment, newlen, move_data);
	default:
		return -EINVAL;
	}
}

static int lustre_grow_msg_v2(struct lustre_msg_v2 *msg, __u32 segment,
			      unsigned int newlen)
{
	char *tail = NULL, *newpos;
	int tail_len = 0, n;

	if (msg->lm_buflens[segment] == newlen)
		goto out;

	if (msg->lm_bufcount > segment + 1) {
		tail = lustre_msg_buf_v2(msg, segment + 1, 0);
		for (n = segment + 1; n < msg->lm_bufcount; n++)
			tail_len += round_up(msg->lm_buflens[n], 8);
	}

	msg->lm_buflens[segment] = newlen;

	if (tail && tail_len) {
		newpos = lustre_msg_buf_v2(msg, segment + 1, 0);
		memmove(newpos, tail, tail_len);
	}
out:
	return lustre_msg_size_v2(msg->lm_bufcount, msg->lm_buflens);
}

/*
 * for @msg, grow @segment to size @newlen.
 * Always move higher buffer forward.
 *
 * return new msg size after growing.
 *
 * CAUTION:
 * - caller must make sure there is enough space in allocated message buffer
 * - caller should NOT keep pointers to msg buffers which higher than @segment
 *   after call shrink.
 */
int lustre_grow_msg(struct lustre_msg *msg, int segment, unsigned int newlen)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		return lustre_grow_msg_v2(msg, segment, newlen);
	default:
		return -EINVAL;
	}
}

static int lustre_unpack_msg_v2(struct lustre_msg_v2 *m, int len)
{
	int swabbed, required_len, i, buflen;

	/* Now we know the sender speaks my language. */
	required_len = lustre_msg_hdr_size_v2(0);
	if (len < required_len) {
		/* can't even look inside the message */
		return -EINVAL;
	}

	swabbed = (m->lm_magic == LUSTRE_MSG_MAGIC_V2_SWABBED);

	if (swabbed) {
		__swab32s(&m->lm_magic);
		__swab32s(&m->lm_bufcount);
		__swab32s(&m->lm_secflvr);
		__swab32s(&m->lm_repsize);
		__swab32s(&m->lm_cksum);
		__swab32s(&m->lm_flags);
		__swab32s(&m->lm_opc);
		BUILD_BUG_ON(offsetof(typeof(*m), lm_padding_3) == 0);
	}

	if (m->lm_bufcount == 0 || m->lm_bufcount > PTLRPC_MAX_BUFCOUNT)
		return -EINVAL;

	required_len = lustre_msg_hdr_size_v2(m->lm_bufcount);
	if (len < required_len) {
		/* didn't receive all the buffer lengths */
		return -EINVAL;
	}

	for (i = 0; i < m->lm_bufcount; i++) {
		if (swabbed)
			__swab32s(&m->lm_buflens[i]);
		buflen = round_up(m->lm_buflens[i], 8);
		if (buflen < 0 || buflen > PTLRPC_MAX_BUFLEN) {
			return -EINVAL;
		}
		required_len += buflen;
	}
	if (len < required_len || required_len > PTLRPC_MAX_BUFLEN)
		return -EINVAL;

	return swabbed;
}

int __lustre_unpack_msg(struct lustre_msg *m, int len)
{
	int required_len, rc;

	/*
	 * We can provide a slightly better error log, if we check the
	 * message magic and version first.  In the future, struct
	 * lustre_msg may grow, and we'd like to log a version mismatch,
	 * rather than a short message.
	 */
	required_len = offsetof(struct lustre_msg, lm_magic) +
				sizeof(m->lm_magic);
	if (len < required_len) {
		/* can't even look inside the message */
		return -EINVAL;
	}

	rc = lustre_unpack_msg_v2(m, len);

	return rc;
}

static inline __u32 lustre_msg_buflen_v2(struct lustre_msg_v2 *m, __u32 n)
{
	if (n >= m->lm_bufcount)
		return 0;

	return m->lm_buflens[n];
}

/**
 * lustre_msg_buflen() - return the length of buffer @n in message @m
 * @m: lustre_msg (request or reply) to look at
 * @n: message index (base 0)
 *
 * returns zero for non-existent message indices
 */
__u32 lustre_msg_buflen(struct lustre_msg *m, __u32 n)
{
	switch (m->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		return lustre_msg_buflen_v2(m, n);
	default:
		return 0;
	}
}

static inline void
lustre_msg_set_buflen_v2(struct lustre_msg_v2 *m, __u32 n, __u32 len)
{
	m->lm_buflens[n] = len;
}

void lustre_msg_set_buflen(struct lustre_msg *m, __u32 n, __u32 len)
{
	switch (m->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		lustre_msg_set_buflen_v2(m, n, len);
		return;
	default:
		return;
	}
}

/*
 * NB return the bufcount for lustre_msg_v2 format, so if message is packed
 * in V1 format, the result is one bigger. (add struct ptlrpc_body).
 */
__u32 lustre_msg_bufcount(struct lustre_msg *m)
{
	switch (m->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		return m->lm_bufcount;
	default:
		return 0;
	}
}

char *lustre_msg_string(struct lustre_msg *m, __u32 index, __u32 max_len)
{
	/* max_len == 0 means the string should fill the buffer */
	char *str;
	__u32 slen, blen;

	switch (m->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		str = lustre_msg_buf_v2(m, index, 0);
		blen = lustre_msg_buflen_v2(m, index);
		break;
	default:
		return NULL;
	}

	if (str == NULL)
		return NULL;

	slen = strnlen(str, blen);

	if (slen == blen)
		return NULL;

	if (blen > PTLRPC_MAX_BUFLEN)
		return NULL;

	if (max_len == 0) {
		if (slen != blen - 1)
			return NULL;
	} else if (slen > max_len) {
		return NULL;
	}

	return str;
}

struct ptlrpc_body *lustre_msg_ptlrpc_body(struct lustre_msg *msg)
{
	return lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF,
				 sizeof(struct ptlrpc_body_v2));
}

enum lustre_msghdr lustre_msghdr_get_flags(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		/* already in host endian */
		return msg->lm_flags;
	default:
		return 0;
	}
}

void lustre_msghdr_set_flags(struct lustre_msg *msg, __u32 flags)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		msg->lm_flags = flags;
		return;
	default:
		return;
	}
}

__u32 lustre_msg_get_flags(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb != NULL)
			return pb->pb_flags;

		return 0;
	}
	fallthrough;
	default:
		/*
		 * flags might be printed in debug code while message
		 * uninitialized
		 */
		return 0;
	}
}

void lustre_msg_add_flags(struct lustre_msg *msg, __u32 flags)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_flags |= flags;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_flags(struct lustre_msg *msg, __u32 flags)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_flags = flags;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_clear_flags(struct lustre_msg *msg, __u32 flags)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_flags &= ~flags;

		return;
	}
	default:
		return;
	}
}

__u32 lustre_msg_get_op_flags(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb != NULL)
			return pb->pb_op_flags;

	}
	fallthrough;
	default:
		return 0;
	}
}

void lustre_msg_add_op_flags(struct lustre_msg *msg, __u32 flags)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_op_flags |= flags;
		return;
	}
	default:
		return;
	}
}

struct lustre_handle *lustre_msg_get_handle(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return NULL;
		return &pb->pb_handle;
	}
	default:
		return NULL;
	}
}

__u32 lustre_msg_get_type(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return PTL_RPC_MSG_ERR;
		return pb->pb_type;
	}
	default:
		return PTL_RPC_MSG_ERR;
	}
}

void lustre_msg_add_version(struct lustre_msg *msg, __u32 version)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_version |= version;
		return;
	}
	default:
		return;
	}
}

__u32 lustre_msg_get_opc(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return 0;
		return pb->pb_opc;
	}
	default:
		return 0;
	}
}

__u64 lustre_msg_get_last_xid(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return 0;
		return pb->pb_last_xid;
	}
	default:
		return 0;
	}
}

__u16 lustre_msg_get_tag(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (!pb)
			return 0;
		return pb->pb_tag;
	}
	default:
		return 0;
	}
}

__u64 lustre_msg_get_last_committed(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return 0;
		return pb->pb_last_committed;
	}
	default:
		return 0;
	}
}

__u64 *lustre_msg_get_versions(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return NULL;
		return pb->pb_pre_versions;
	}
	default:
		return NULL;
	}
}

__u64 lustre_msg_get_transno(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return 0;
		return pb->pb_transno;
	}
	default:
		return 0;
	}
}

int lustre_msg_get_status(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb != NULL)
			return pb->pb_status;
	}
	fallthrough;
	default:
		/*
		 * status might be printed in debug code while message
		 * uninitialized
		 */
		return -EINVAL;
	}
}

__u64 lustre_msg_get_slv(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return -EINVAL;
		return pb->pb_slv;
	}
	default:
		return -EINVAL;
	}
}


void lustre_msg_set_slv(struct lustre_msg *msg, __u64 slv)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return;
		pb->pb_slv = slv;
		return;
	}
	default:
		return;
	}
}

__u32 lustre_msg_get_limit(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return -EINVAL;
		return pb->pb_limit;
	}
	default:
		return -EINVAL;
	}
}


void lustre_msg_set_limit(struct lustre_msg *msg, __u64 limit)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return;
		pb->pb_limit = limit;
		return;
	}
	default:
		return;
	}
}

__u32 lustre_msg_get_conn_cnt(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return 0;
		return pb->pb_conn_cnt;
	}
	default:
		return 0;
	}
}

__u32 lustre_msg_get_magic(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		return msg->lm_magic;
	default:
		return 0;
	}
}

timeout_t lustre_msg_get_timeout(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);

		if (pb == NULL)
			return 0;
		return pb->pb_timeout;
	}
	default:
		return 0;
	}
}

timeout_t lustre_msg_get_service_timeout(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);

		if (pb == NULL)
			return 0;
		return pb->pb_service_time;
	}
	default:
		return 0;
	}
}

int lustre_msg_get_projid(struct lustre_msg *msg, __u32 *projid)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb;

		if (msg->lm_buflens[MSG_PTLRPC_BODY_OFF] <
		    sizeof(struct ptlrpc_body))
			return -EOPNOTSUPP;

		pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF,
					  sizeof(struct ptlrpc_body));

		if (!pb || !(pb->pb_flags & MSG_PACK_PROJID))
			return -EOPNOTSUPP;

		if (projid)
			*projid = pb->pb_projid;

		return 0;
	}
	default:
		return -EOPNOTSUPP;
	}
}

int lustre_msg_get_uid_gid(struct lustre_msg *msg, __u32 *uid, __u32 *gid)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb;

		/* the old pltrpc_body_v2 is smaller; doesn't include uid/gid */
		if (msg->lm_buflens[MSG_PTLRPC_BODY_OFF] <
		    sizeof(struct ptlrpc_body))
			return -EOPNOTSUPP;

		pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF,
					  sizeof(struct ptlrpc_body));

		if (!pb || !(pb->pb_flags & MSG_PACK_UID_GID))
			return -EOPNOTSUPP;

		if (uid)
			*uid = pb->pb_uid;
		if (gid)
			*gid = pb->pb_gid;

		return 0;
	}
	default:
		return -EOPNOTSUPP;
	}
}

char *lustre_msg_get_jobid(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb;

		/* the old pltrpc_body_v2 is smaller; doesn't include jobid */
		if (msg->lm_buflens[MSG_PTLRPC_BODY_OFF] <
		    sizeof(struct ptlrpc_body))
			return NULL;

		pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF,
					  sizeof(struct ptlrpc_body));
		if (!pb)
			return NULL;

		/* If clients send unterminated jobids, terminate them here
		 * so that there is no chance of string overflow later.
		 */
		if (pb->pb_jobid[LUSTRE_JOBID_SIZE - 1] != '\0')
			pb->pb_jobid[LUSTRE_JOBID_SIZE - 1] = '\0';

		return pb->pb_jobid;
	}
	default:
		return NULL;
	}
}

__u32 lustre_msg_get_cksum(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		return msg->lm_cksum;
	default:
		return 0;
	}
}

__u64 lustre_msg_get_mbits(struct lustre_msg *msg)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		if (pb == NULL)
			return 0;
		return pb->pb_mbits;
	}
	default:
		return 0;
	}
}

void lustre_msg_set_handle(struct lustre_msg *msg, struct lustre_handle *handle)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_handle = *handle;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_type(struct lustre_msg *msg, __u32 type)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_type = type;
		return;
		}
	default:
		return;
	}
}

void lustre_msg_set_opc(struct lustre_msg *msg, __u32 opc)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_opc = opc;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_last_xid(struct lustre_msg *msg, __u64 last_xid)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_last_xid = last_xid;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_tag(struct lustre_msg *msg, __u16 tag)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_tag = tag;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_last_committed(struct lustre_msg *msg, __u64 last_committed)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_last_committed = last_committed;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_versions(struct lustre_msg *msg, __u64 *versions)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_pre_versions[0] = versions[0];
		pb->pb_pre_versions[1] = versions[1];
		pb->pb_pre_versions[2] = versions[2];
		pb->pb_pre_versions[3] = versions[3];
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_transno(struct lustre_msg *msg, __u64 transno)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_transno = transno;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_status(struct lustre_msg *msg, __u32 status)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_status = status;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_conn_cnt(struct lustre_msg *msg, __u32 conn_cnt)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_conn_cnt = conn_cnt;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_timeout(struct lustre_msg *msg, timeout_t timeout)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);
		pb->pb_timeout = timeout;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_service_timeout(struct lustre_msg *msg,
				    timeout_t service_timeout)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);

		pb->pb_service_time = service_timeout;
		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_projid(struct lustre_msg *msg, __u32 projid)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		__u32 opc = lustre_msg_get_opc(msg);
		struct ptlrpc_body *pb;

		/* Don't set projid for ldlm ast RPCs */
		if (!opc || opc == LDLM_BL_CALLBACK ||
		    opc == LDLM_CP_CALLBACK || opc == LDLM_GL_CALLBACK)
			return;

		pb = lustre_msg_buf_v2(msg, MSG_PTLRPC_BODY_OFF,
				       sizeof(struct ptlrpc_body));

		pb->pb_projid = projid;
		pb->pb_flags |= MSG_PACK_PROJID;

		return;
	}
	default:
		return;
	}
}

void lustre_msg_set_cksum(struct lustre_msg *msg, __u32 cksum)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2:
		msg->lm_cksum = cksum;
		return;
	default:
		return;
	}
}

void lustre_msg_set_mbits(struct lustre_msg *msg, __u64 mbits)
{
	switch (msg->lm_magic) {
	case LUSTRE_MSG_MAGIC_V2: {
		struct ptlrpc_body *pb = lustre_msg_ptlrpc_body(msg);

		pb->pb_mbits = mbits;
		return;
	}
	default:
		return;
	}
}
