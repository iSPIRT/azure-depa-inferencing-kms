#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# This script outputs a COSE Sign1 document, switching on the env variable
# `USE_AKV`.
#  - In the local key case, doing a simple one step signing.
#  - In the AKV key case, using the two step process which prepares the document
#    given the payload and signing cert, then uses AKV to sign the JSON output, and
#    then finally calling finish to output the final COSE Sign1 document.

set -eEo pipefail

ccf-sign() {

    set -x 

    content=$1
    msg_type=${2:-"proposal"}
    extra_args="${@:3}"
    USE_AKV=${USE_AKV:-"false"}

    if [[ "$USE_AKV" == "false" ]]; then
        ccf_cose_sign1 \
            --content $content \
            --signing-cert ${KMS_MEMBER_CERT_PATH} \
            --signing-key ${KMS_MEMBER_PRIVK_PATH} \
            --ccf-gov-msg-type $msg_type \
            --ccf-gov-msg-created_at $(date -Is) \
            $extra_args
    else
        creation_time=$(date -u +"%Y-%m-%dT%H:%M:%S")

        export AKV_URL=$( \
            az keyvault key show \
            --vault-name $AKV_VAULT_NAME \
            --name $AKV_KEY_NAME \
            --query key.kid \
            --output tsv)

        # Prepare the data to be signed and save to temp file
        prepared_data=$(mktemp)
        signature=$(mktemp)
        
        ccf_cose_sign1_prepare \
            --ccf-gov-msg-type $msg_type \
            --ccf-gov-msg-created_at $creation_time \
            --content $content \
            --signing-cert ${KMS_MEMBER_CERT_PATH} \
            $extra_args > $prepared_data
        
        # Use Azure Key Vault REST API to sign the data
        # The REST API expects the full JSON payload from ccf_cose_sign1_prepare
        # and returns {"kid": "...", "value": "..."} which is what ccf_cose_sign1_finish expects
        # Get access token for Key Vault
        bearer_token=$(az account get-access-token \
            --resource https://vault.azure.net \
            --query accessToken \
            --output tsv)
        
        # Call the REST API sign endpoint with the prepared data
        # The API expects the full JSON: {"alg": "...", "value": "..."}
        http_code=$(curl -X POST -s -w "%{http_code}" \
            -H "Authorization: Bearer $bearer_token" \
            -H "Content-Type: application/json" \
            "${AKV_URL}/sign?api-version=7.2" \
            --data @$prepared_data \
            -o $signature)
        
        if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
            echo "ERROR: Azure Key Vault returned HTTP $http_code" >&2
            jq . $signature >&2 2>/dev/null || cat $signature >&2
            echo "" >&2
        fi
        
        # Verify the signature was retrieved and is valid JSON
        if [[ ! -s "$signature" ]] || ! jq -e '.kid and .value' $signature >/dev/null 2>&1; then
            echo "ERROR: Invalid signature response from Azure Key Vault" >&2
            jq . $signature >&2 2>/dev/null || cat $signature >&2
            echo "" >&2
            rm -f $prepared_data $signature
            exit 1
        fi
        cose_output=$(mktemp)
        ccf_cose_sign1_finish \
            --ccf-gov-msg-type $msg_type \
            --ccf-gov-msg-created_at $creation_time \
            --content $content \
            --signing-cert ${KMS_MEMBER_CERT_PATH} \
            --signature $signature \
            $extra_args > $cose_output
        
        # Check if ccf_cose_sign1_finish produced output
        if [[ ! -s "$cose_output" ]]; then
            echo "ERROR: ccf_cose_sign1_finish produced no output" >&2
            rm -f $prepared_data $signature $cose_output
            exit 1
        fi
        
        # Output the COSE Sign1 document (binary data to stdout)
        head -c $(wc -c < $cose_output) $cose_output
        
        rm -rf $prepared_data $signature $cose_output
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    ccf-sign "$@"
fi
