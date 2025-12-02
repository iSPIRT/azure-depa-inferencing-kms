#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

proposals() {

    set -x 
    
    # Save the COSE input to a temp file for debugging
    cose_input=$(mktemp)
    dd of=$cose_input bs=4096 2>/dev/null || cat > $cose_input
    
    cose_size=$(wc -c < $cose_input)
    echo "COSE input size: $cose_size bytes" >&2
    
    # Show first and last bytes for debugging
    if command -v od >/dev/null 2>&1; then
        echo "First 32 bytes (hex):" >&2
        head -c 32 $cose_input | od -An -tx1 | head -n 2 >&2
        echo "Last 32 bytes (hex):" >&2
        tail -c 32 $cose_input | od -An -tx1 >&2
    elif command -v hexdump >/dev/null 2>&1; then
        echo "First 32 bytes (hex):" >&2
        head -c 32 $cose_input | hexdump -C | head -n 2 >&2
        echo "Last 32 bytes (hex):" >&2
        tail -c 32 $cose_input | hexdump -C >&2
    fi
    echo "" >&2
    
    # Verify it starts with COSE_Sign1 tag
    first_byte=$(head -c 1 $cose_input | od -An -tx1 | tr -d ' \n')
    if [[ "$first_byte" != "d2" ]]; then
        echo "WARNING: COSE input does not start with COSE_Sign1 tag (expected 0xd2, got 0x$first_byte)" >&2
    else
        echo "COSE input starts with correct COSE_Sign1 tag (0xd2)" >&2
    fi
    echo "" >&2
    
    # Make the request
    echo "Sending COSE document to $KMS_URL/app/proposals" >&2
    response=$(curl -X POST -s -w "\n%{http_code}" \
        -H "Content-Type: application/cose" \
        --data-binary @$cose_input \
        --cacert $KMS_SERVICE_CERT_PATH \
        "$KMS_URL/app/proposals" 2>&1)
    
    # Extract HTTP code and body
    http_code=$(echo "$response" | tail -n 1)
    response_body=$(echo "$response" | head -n -1)
    
    echo "HTTP response code: $http_code" >&2
    echo "Response body:" >&2
    echo "$response_body" | jq . 2>/dev/null || echo "$response_body" >&2
    echo "" >&2
    
    # Output the response (including HTTP code) to stdout
    echo "$response"
    
    # Cleanup
    rm -f $cose_input
}

proposals "$@"