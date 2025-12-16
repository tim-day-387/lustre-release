#!/bin/bash
#
# find lustre/llite/ -name *.[ch] -exec /home/timothy/Programming/lustre-release/headers.sh {} \;
#

file="$1"
header_end="$(awk '/#include/ {line=NR} END {if (line) print line}' $file)"

clang-format-20 --sort-includes -lines="1:$header_end" -i "$file"
