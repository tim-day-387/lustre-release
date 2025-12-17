#!/bin/bash

function find_kernel_dirs() {
	find lustre/ -mindepth 1 -maxdepth 1 -type d |
	    grep -v utils |
	    grep -v scripts |
	    grep -v kernel_patches |
	    grep -v conf |
	    grep -v include |
	    grep -v tests |
	    grep -v doc
	echo "lnet/klnds"
	echo "lnet/lnet"
	echo "lnet/include"
	echo "include"
	echo "libcfs/libcfs"
}

find $(find_kernel_dirs) \
     -name *.[ch] \
     -exec unifdef -s {} \; \
    | sort | uniq -c | sort
