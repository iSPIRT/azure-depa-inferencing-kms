#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Get an access token for a managed identity using IMDS (Instance Metadata Service)
# This works when running on Azure resources (VMs, App Services, etc.)

# Usage:
#   CLIENT_ID="<managed-identity-client-id>" RESOURCE="https://vault.azure.net" ./get_managed_identity_token.sh

set -e

# Default resource is Key Vault if not specified
RESOURCE=${RESOURCE:-"https://vault.azure.net"}
CLIENT_ID=${CLIENT_ID:-""}
API_VERSION=${API_VERSION:-"2018-02-01"}

# IMDS endpoint
IMDS_ENDPOINT="http://169.254.169.254/metadata/identity/oauth2/token"

echo "Getting managed identity token..." >&2
echo "Resource: $RESOURCE" >&2
if [ -n "$CLIENT_ID" ]; then
    echo "Client ID: $CLIENT_ID" >&2
fi
echo ""

# Build the curl command
if [ -n "$CLIENT_ID" ]; then
    # With specific client ID
    TOKEN=$(curl -s -H "Metadata: true" \
        "${IMDS_ENDPOINT}?api-version=${API_VERSION}&resource=${RESOURCE}&client_id=${CLIENT_ID}" \
        | jq -r '.access_token')
else
    # Without client ID (uses system-assigned or default user-assigned identity)
    TOKEN=$(curl -s -H "Metadata: true" \
        "${IMDS_ENDPOINT}?api-version=${API_VERSION}&resource=${RESOURCE}" \
        | jq -r '.access_token')
fi

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
    echo "Error: Failed to obtain access token" >&2
    exit 1
fi

echo "$TOKEN"

