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
#include <stdbool.h>
#include <getopt.h>

#include "lnetdump.h"

volatile bool exiting = false;

static void sig_int(int signo) {
	exiting = true;
}

static void usage(const char *prog) {
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"\n"
		"Options:\n"
		"  --help            Show this help and exit\n"
		"  --version         Show version information and exit\n"
		"  --input=bpf       Select input source (only 'bpf' supported)\n"
		"  --output=print    Select output method (only 'print' supported)\n"
		"\n",
		prog);
}

int main(int argc, char **argv)
{
	const struct lnetdump_output_methods *lom = &print_output_methods;
	lnetdump_input_fn input_fn = lnetdump_bpf_input;
	const char *output = "print";
	const char *input = "bpf";
	int rc = 0;
	int c;

	static struct option long_opts[] = {
		{"help",    no_argument,       0, 'h'},
		{"version", no_argument,       0, 'v'},
		{"input",   required_argument, 0, 'i'},
		{"output",  required_argument, 0, 'o'},
		{"pretty",  required_argument, 0, 'p'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "hvi:o:p:", long_opts, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			return 0;
		case 'v':
			printf("lnetdump version %s (%s)\n",
			       VERSION_STRING, LUSTRE_VERSION_STRING);
			return 0;
		case 'i':
			if (strcmp(optarg, "bpf") == 0) {
				input_fn = lnetdump_bpf_input;
				input = optarg;
				break;
			}
			fprintf(stderr, "Unsupported input: %s\n", optarg);
			return 1;
		case 'o':
			if (strcmp(optarg, "print") == 0) {
				lom = &print_output_methods;
				output = optarg;
				break;
			}
			fprintf(stderr, "Unsupported output: %s\n", optarg);
			return 1;
		default:
			rc = lom->lom_parse_args(c, optarg);
			if (rc) {
				usage(argv[0]);
				return rc;
			}
			break;
		}
	}

	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);

	if (!input_fn || !lom) {
		fprintf(stderr, "Unsupported input/output combination\n");
		return 1;
	}

	req_layout_init();

	input_fn(lom);

	return 0;
}
