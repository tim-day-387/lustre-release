#!/bin/bash
# test_compile_headers.sh
# Usage: ./test_compile_headers.sh /path/to/headers

# Directory containing headers
HEADER_DIR="$1"

# Include paths for compilation
INCLUDE_PATHS=(-I include -I lustre/include -I lustre/include/uapi -I lnet/include -I lnet/include/uapi)

if [[ -z "$HEADER_DIR" ]]; then
    echo "Usage: $0 /path/to/headers"
    exit 1
fi

# Find all .h files
headers=$(find "$HEADER_DIR" -type f -name "*.h")

if [[ -z "$headers" ]]; then
    echo "No headers found in $HEADER_DIR"
    exit 1
fi

echo "Testing compilation of headers in $HEADER_DIR"

for header in $headers; do
    echo -n "Compiling $header ... "
    gcc -fsyntax-only "${INCLUDE_PATHS[@]}" "$header" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        echo "OK"
    else
        echo "FAILED"
    fi
done

echo "Header compilation test finished."
