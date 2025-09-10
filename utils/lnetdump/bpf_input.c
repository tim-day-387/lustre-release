// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Timothy Day <timday@amazon.com>
 */

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "lnetdump.skel.h"
#include "lnetdump.h"
#include "common.h"

int lnetdump_bpf_input(const struct lnetdump_output_methods *lom)
{
    struct lnetdump_bpf *skel = NULL;
    struct perf_buffer *pb = NULL;
    int err;

    /* Open BPF application */
    skel = lnetdump_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = lnetdump_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach tracepoints/kprobes/etc */
    err = lnetdump_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach skeleton: %d\n", err);
        goto cleanup;
    }

    /* Create perf buffer for "events" map */
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8,
                          lom->lom_sample_cb, lom->lom_lost_cb,
			  NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer\n");
        goto cleanup;
    }

    /* Poll loop */
    while (!exiting) {
        err = perf_buffer__poll(pb, 100 /* ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    lnetdump_bpf__destroy(skel);
    return err != 0;
}
