#!/usr/bin/bash
trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2

PYTHON=${PYTHON:-python3}

while true; do
	file=$DIR/$((RANDOM % MAX))
	$PYTHON -c "
import mmap, os, signal
signal.signal(signal.SIGBUS, lambda s, f: (_ for _ in ()).throw(OSError('SIGBUS')))
try:
	fd = os.open('$file', os.O_RDWR | os.O_CREAT, 0o644)
	os.ftruncate(fd, 4096)
	with mmap.mmap(fd, 4096) as m:
		m[0:8] = b'mmaptest'
		m.flush()
	os.close(fd)
except Exception:
	pass
" 2>/dev/null
done
