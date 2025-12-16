#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"

tmp_headers="$(mktemp)"
tmp_includes="$(mktemp)"

trap 'rm -f "$tmp_headers" "$tmp_includes"' EXIT

#
# 1. Build list of headers that exist in the repo
#    Store both full paths and basenames
#
find "$ROOT" -type f -name '*.h' \
    | sed "s|^$ROOT/||" \
    | xargs -n1 basename | sort > "$tmp_headers"

#
# 2. Extract all include statements (normalized)
#
find "$ROOT" -type f \( -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp' \) -print0 |
xargs -0 grep -hE '^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"].*[>"]' |
sed -E '
    s@//.*@@;
    s@^[[:space:]]*#[[:space:]]*include[[:space:]]*[<"]@@;
    s@[>"]$@@
' |
grep -E '^[A-Za-z0-9_]+\.h$' |
xargs -n1 basename |
sort > "$tmp_includes"

#cat "$tmp_headers"

#
# 3. Match includes against real headers and count
#
grep -F -f "$tmp_headers" "$tmp_includes" |
sort |
uniq -c |
sort -nr
