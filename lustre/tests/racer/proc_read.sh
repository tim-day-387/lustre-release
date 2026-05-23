#!/usr/bin/bash
trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2

while true; do
	$LCTL get_param llite.*.* > /dev/null 2>&1
	sleep 1
done
