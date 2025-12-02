#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

proposals() {

    set -x 
    
    # Save the COSE input to a temp file
    cose_input=$(mktemp)
    dd of=$cose_input bs=4096 2>/dev/null || cat > $cose_input
    
    # Make the request
    response=$(curl -X POST -s -w "\n%{http_code}" \
        -H "Content-Type: application/cose" \
        --data-binary @$cose_input \
        --cacert $KMS_SERVICE_CERT_PATH \
        "$KMS_URL/app/proposals" 2>&1)
    
    # Check for curl errors
    curl_exit_code=$?
    if [[ $curl_exit_code -ne 0 ]]; then
        echo "ERROR: curl failed with exit code $curl_exit_code" >&2
        echo "Response: $response" >&2
    fi
    
    # Extract HTTP code and body
    http_code=$(echo "$response" | tail -n 1)
    response_body=$(echo "$response" | head -n -1)
    
    echo "HTTP response code: $http_code" >&2
    echo "Response body:" >&2
    if echo "$response_body" | jq . >&2 2>/dev/null; then
        # If it's valid JSON, extract error message if present
        error_msg=$(echo "$response_body" | jq -r '.error.message // .errorMessage // empty' 2>/dev/null)
        if [[ -n "$error_msg" ]]; then
            echo "Error message: $error_msg" >&2
        fi
    else
        echo "$response_body" >&2
    fi
    echo "" >&2
    
    # If 401, provide helpful context
    if [[ "$http_code" == "401" ]]; then
        echo "NOTE: 401 Unauthorized typically means:" >&2
        echo "  - The member certificate doesn't have 'Administrator' or 'Contributor' role in ACL" >&2
        echo "  - The COSE signature is invalid or doesn't match the certificate" >&2
        echo "  - The member certificate is not registered in the ledger" >&2
        echo "" >&2
    fi
    
    # Output the response (including HTTP code) to stdout
    echo "$response"
    
    # Cleanup
    rm -f $cose_input
}

proposals "$@"