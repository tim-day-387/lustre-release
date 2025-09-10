// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * eBPF program to capture packets from LNet. This is LND
 * agnosic - meaning this should work regardless of network
 * type, even loopback. Packets are returned as perf events
 * to be processed by the userspace lnetdump tool.
 *
 * Author: Timothy Day <timday@amazon.com>
 */

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

/* Magic number; this could be increased
 * if we find we are missing events.
 */
#define LNET_MSG_QUEUE 8192

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, LNET_MSG_QUEUE);
	__type(key, u32);
	__type(value, u32);
} events SEC(".maps");

struct lnet_msg_val {
	struct lnet_msg __kptr *lmv_msg;
	struct data_t lmv_data;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, LNET_MSG_QUEUE);
	__type(key, u64);
	__type(value, struct lnet_msg_val);
} lnet_msg_map SEC(".maps");

/* See the cooresponding definitions in lnet/lnet/module.c */
struct lnet_msg *bpf_lnet_get_msg(struct lnet_msg *msg__ign) __ksym;
void bpf_lnet_put_msg(struct lnet_msg *msg) __ksym;
void bpf_lnet_load_bytes(void *dest, int dest__sz,
			 unsigned int doffset,
			 struct lnet_msg *msg__ign) __ksym;
void bpf_lnet_lazy_load_bytes(void *dest, int dest__sz,
			      unsigned int doffset,
			      struct lnet_msg *msg) __ksym;
void bpf_lnet_ev_load_bytes(void *dest, int dest__sz,
			    unsigned int doffset,
			    struct lnet_event *ev__ign) __ksym;

static int bpf_read_lnet_msg(struct data_t *data, struct lnet_msg *msg,
			     int send_or_recv)
{
	if (!msg || !data)
		return 0;

	bpf_probe_read(&data->msg_type, sizeof(data->msg_type), &msg->msg_type);
	bpf_probe_read(&data->msg_len, sizeof(data->msg_len), &msg->msg_len);

	if (data->msg_type == LNET_MSG_PUT) {
		bpf_probe_read(&data->msg_ptl, sizeof(data->msg_ptl),
			       &msg->msg_hdr.msg.put.ptl_index);
		bpf_probe_read(&data->msg_mbits, sizeof(data->msg_mbits),
			       &msg->msg_hdr.msg.put.match_bits);
	} else if (data->msg_type == LNET_MSG_GET) {
		bpf_probe_read(&data->msg_ptl, sizeof(data->msg_ptl),
			       &msg->msg_hdr.msg.get.ptl_index);
		bpf_probe_read(&data->msg_mbits, sizeof(data->msg_mbits),
			       &msg->msg_hdr.msg.get.match_bits);
	}

	data->send_or_recv = send_or_recv;

	return 0;
}

SEC("fentry/lnet_ni_send")
int BPF_PROG(lnet_ni_send, struct lnet_ni *ni,
	     struct lnet_msg *msg)
{
	struct lnet_msg *msg_rc = NULL;
	struct data_t data = {};
	int rc = 0;

	if (!msg)
		return 0;

	msg_rc = bpf_lnet_get_msg(msg);
	if (!msg_rc)
		return 0;

	rc = bpf_read_lnet_msg(&data, msg_rc, 0);

	bpf_lnet_load_bytes(&data.msg_payload, PAYLOAD_SIZE, 0, msg_rc);

	bpf_lnet_put_msg(msg_rc);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return rc;
}

/* TODO: Should this fail? And how should we handle it? */
static int lnet_msg_map_insert(struct lnet_msg *msg)
{
	struct lnet_msg_val local = {};
	struct lnet_msg_val *v = NULL;
	struct lnet_msg *old = NULL;
	u64 key = (u64)msg;
	int rc = 0;

	rc = bpf_map_update_elem(&lnet_msg_map, &key, &local, 0);
	if (rc) {
		bpf_lnet_put_msg(msg);
		return 0;
	}

	/* We must do a second lookup to get the true address
	 * assigned to the value in the map
	 */
	v = bpf_map_lookup_elem(&lnet_msg_map, &key);
	if (!v) {
		bpf_lnet_put_msg(msg);
		return 0;
	}

	bpf_lnet_lazy_load_bytes(&v->lmv_data.msg_payload, PAYLOAD_SIZE, 0, msg);

	old = bpf_kptr_xchg(&v->lmv_msg, msg);
	if (old)
		bpf_lnet_put_msg(old);

	return 0;
}

SEC("fentry/lnet_ni_recv")
int BPF_PROG(lnet_ni_recv_entry, struct lnet_ni *ni,
	     void *private, struct lnet_msg *msg)
{
	struct lnet_msg *msg_rc = NULL;
	u32 type = 0;

	bpf_probe_read(&type, sizeof(type), &msg->msg_type);
	if (type != LNET_MSG_REPLY)
		return 0;

	msg_rc = bpf_lnet_get_msg(msg);
	if (!msg_rc)
		return 0;

	return lnet_msg_map_insert(msg_rc);
}

SEC("fexit/lnet_ni_recv")
int BPF_PROG(lnet_ni_recv_exit, struct lnet_ni *ni,
	     void *private, struct lnet_msg *msg)
{
	struct lnet_msg_val *val = NULL;
	struct lnet_msg *msg_rc = NULL;
	struct data_t *data;
	u64 key = (u64)msg;

	val = bpf_map_lookup_elem(&lnet_msg_map, &key);
	if (!val)
		return 0;

	msg_rc = bpf_kptr_xchg(&val->lmv_msg, NULL);
	if (!msg_rc)
		return 0;

	data = &val->lmv_data;

	bpf_read_lnet_msg(data, msg_rc, 1);

	bpf_lnet_put_msg(msg_rc);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, sizeof(struct data_t));

	return 0;
}

/* TODO: These event handlers only exist to capture GETs, which
 * won't normally get routed via lnet_ni_recv(). Ideally, we'd
 * capture all recv side messages via MD events - but we need to
 * set up the lazy packet capturing with bpf_lnet_lazy_load_bytes().
 * We can't read the MD at event time because events are not
 * guaranteed to arrive in order i.e. we may see UNLINK before PUT.
 */
static int lnet_event_hdlr(struct data_t *data, struct lnet_event *ev)
{
	if (!ev)
		return 1;

	bpf_probe_read(&data->msg_type, sizeof(data->msg_type), &ev->msg_type);
	bpf_probe_read(&data->msg_len, sizeof(data->msg_len), &ev->rlength);
	bpf_probe_read(&data->msg_ptl, sizeof(data->msg_ptl), &ev->pt_index);
	bpf_probe_read(&data->send_or_recv, sizeof(data->send_or_recv), &ev->type);
	bpf_probe_read(&data->msg_mbits, sizeof(data->msg_mbits), &ev->match_bits);

	if (data->send_or_recv == LNET_EVENT_SEND ||
	    data->send_or_recv == LNET_EVENT_UNLINK)
		return 1;

	if (data->send_or_recv == LNET_EVENT_PUT)
		bpf_lnet_ev_load_bytes(&data->msg_payload, PAYLOAD_SIZE, 0, ev);

	data->send_or_recv = 1;

	return 0;
}

SEC("fentry/lnet_ping_event_handler")
int BPF_PROG(lnet_ping_event_handler, struct lnet_event *ev)
{
	struct data_t data = {};

	if (lnet_event_hdlr(&data, ev))
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

SEC("fentry/lnet_ping_target_event_handler")
int BPF_PROG(lnet_ping_target_event_handler, struct lnet_event *ev)
{
	struct data_t data = {};

	if (lnet_event_hdlr(&data, ev))
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

SEC("fentry/lnet_push_target_event_handler")
int BPF_PROG(lnet_push_target_event_handler, struct lnet_event *ev)
{
	struct data_t data = {};

	if (lnet_event_hdlr(&data, ev))
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

SEC("fentry/ptlrpc_master_callback")
int BPF_PROG(ptlrpc_master_callback, struct lnet_event *ev)
{
	struct data_t data = {};

	if (lnet_event_hdlr(&data, ev))
		return 0;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
