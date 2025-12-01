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

    echo "--------------------------------"
    echo "content: $content"
    echo "msg_type: $msg_type"
    echo "extra_args: $extra_args"
    echo "USE_AKV: $USE_AKV"
    echo "KMS_MEMBER_CERT_PATH: $KMS_MEMBER_CERT_PATH"
    echo "KMS_MEMBER_PRIVK_PATH: $KMS_MEMBER_PRIVK_PATH"
    echo "AKV_VAULT_NAME: $AKV_VAULT_NAME"
    echo "AKV_KEY_NAME: $AKV_KEY_NAME"
    echo "$(< $content)"
    echo "--------------------------------"


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
        echo "AKV_URL: $AKV_URL"

        # Prepare the data to be signed and save to temp file
        prepared_data=$(mktemp)
        signature=$(mktemp)
        
        echo "Preparing COSE Sign1 data..."
        ccf_cose_sign1_prepare \
            --ccf-gov-msg-type $msg_type \
            --ccf-gov-msg-created_at $creation_time \
            --content $content \
            --signing-cert ${KMS_MEMBER_CERT_PATH} \
            $extra_args > $prepared_data
        echo "Prepared data saved to: $prepared_data"
        echo "Prepared data content:"
        echo "$(< $prepared_data)"
        echo ""
        
        # Extract algorithm and value from the JSON prepared data
        # The prepared data is JSON with format: {"alg": "...", "value": "base64..."}
        alg=$(jq -r '.alg' $prepared_data)
        value=$(jq -r '.value' $prepared_data)
        echo "Extracted algorithm: $alg"
        echo "Extracted value length: ${#value} characters"
        
        # Use az keyvault key sign to sign the data
        echo "Signing with Azure Key Vault..."
        sig_value=$(az keyvault key sign \
            --vault-name $AKV_VAULT_NAME \
            --name $AKV_KEY_NAME \
            --algorithm $alg \
            --digest $value \
            | jq -r '.signature')
        echo "Signature value: $sig_value"
        echo "Signature value length: ${#sig_value} characters"
        echo "{\"kid\":\"$AKV_URL\",\"value\":\"$sig_value\"}" > $signature
        
        echo "Finishing COSE Sign1 document..."
        ccf_cose_sign1_finish \
            --ccf-gov-msg-type $msg_type \
            --ccf-gov-msg-created_at $creation_time \
            --content $content \
            --signing-cert ${KMS_MEMBER_CERT_PATH} \
            --signature $signature \
            $extra_args
        
        rm -rf $prepared_data $signature
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    ccf-sign "$@"
fi
