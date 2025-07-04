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

void LNetIO_ev_handler(struct lnet_event *ev)
{
	struct lnet_blk_rdma *rdma = ev->md_user_ptr;

	LASSERT(!in_interrupt());

	CDEBUG(D_NET, "LNet event status %d type %d up %p\n",
	       ev->status, ev->type, ev->md_user_ptr);

	switch (ev->type) {
	case LNET_EVENT_ACK:
	case LNET_EVENT_REPLY:
		LASSERT(rdma);
		lnet_blk_print_rdma(rdma);
		complete(&rdma->ln_ev_comp);
		return;
	default:
		return;
	}
}
