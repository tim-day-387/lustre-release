/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Defintions shared between eBPF code and normal userspace
 * code.
 *
 * Author: Timothy Day <timday@amazon.com>
 */

#define PAYLOAD_SIZE 256

struct data_t {
    __u32 send_or_recv;
    __u32 msg_type;
    __u32 msg_len;
    __u32 msg_ptl;
    __u64 msg_mbits;
    __u8 msg_payload[PAYLOAD_SIZE];
};
