#!/usr/bin/env bash

set -eu

functions_file="$1"
threshold="$2"

while IFS= read -r func || [[ -n "$func" ]]; do
    # Skip empty lines
    [[ -z "$func" ]] && continue

    count=$(git grep -w "$func" | wc -l)

    if (( count <= threshold )); then
        printf "%s - %d\n" "$func" "$count"
    fi
done < "$functions_file"
