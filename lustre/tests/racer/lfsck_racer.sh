#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0
trap 'kill $(jobs -p) 2>/dev/null' EXIT

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/../..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
trap - ERR
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

LFSCK_PERIOD=${LFSCK_PERIOD:-30}

while true; do
	sleep $LFSCK_PERIOD || break
	run_lfsck || true
done
