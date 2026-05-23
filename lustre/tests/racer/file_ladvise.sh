#!/usr/bin/bash
trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2

while true; do
	file=$DIR/$((RANDOM % MAX))
	$LFS ladvise -a willread "$file" 2>/dev/null
	$LFS ladvise -a dontneed "$file" 2>/dev/null
done
