#!/usr/bin/bash
trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2

while true; do
	file=$DIR/$((RANDOM % MAX))
	flock -x "$file" true 2>/dev/null
	flock -s "$file" true 2>/dev/null
done
