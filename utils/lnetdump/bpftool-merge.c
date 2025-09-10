// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * bpftool does not natively support merging BTF information
 * from separate sources. We need to merge the BTF from
 * Lustre with that from the kernel so we could generate
 * a header file for eBPF CO-RE. This tool uses libbpf
 * to achieve that.
 *
 * Usage:
 *   ./bpftool-merge file1.btf file2.btf merged.btf
 *
 * Author: Timothy Day <timday@amazon.com>
 */

#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static void die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

static void save_btf(const struct btf *btf, const char *path)
{
	const void *data;
	__u32 size;
	FILE *f;

	data = btf__raw_data(btf, &size);
	if (!data || size == 0) {
		fprintf(stderr, "failed to get raw BTF data\n");
		exit(EXIT_FAILURE);
	}

	f = fopen(path, "wb");
	if (!f)
		die("fopen");

	if (fwrite(data, 1, size, f) != size) {
		perror("fwrite");
		fclose(f);
		exit(EXIT_FAILURE);
	}

	fclose(f);
}

/* TODO: There may be a native way to do this... */
static struct btf *btf__parse_raw_or_elf(const char *file)
{
	struct btf *btf = NULL;

	btf = btf__parse_raw(file);
	if (!btf)
		btf = btf__parse_elf(file, NULL);

	return btf;
}

int main(int argc, char **argv)
{
	struct btf *btf1 = NULL, *btf2 = NULL;
	const char *file1, *file2, *outfile;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <file1.btf> <file2.btf> <merged.btf>\n", argv[0]);
		return EXIT_FAILURE;
	}

	file1 = argv[1];
	file2 = argv[2];
	outfile = argv[3];

	btf1 = btf__parse_raw_or_elf(file1);
	if (!btf1)
		die("btf parse file1");

	btf2 = btf__parse_raw_or_elf(file2);
	if (!btf2)
		die("btf parse file2");

	btf__add_btf(btf1, btf2);

	if (btf__dedup(btf1, NULL))
		die("btf__dedup");

	save_btf(btf1, outfile);

	btf__free(btf2);
	btf__free(btf1);

	printf("Merged BTF written to %s\n", outfile);

	return EXIT_SUCCESS;
}
