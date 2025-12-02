#!/bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Diagnostic script to verify Azure Key Vault permissions for signing

set -e

if [ -z "$AKV_VAULT_NAME" ] || [ -z "$AKV_KEY_NAME" ]; then
    echo "Error: AKV_VAULT_NAME and AKV_KEY_NAME must be set"
    exit 1
fi

echo "=== Azure Key Vault Permission Diagnostics ==="
echo "Vault Name: $AKV_VAULT_NAME"
echo "Key/Certificate Name: $AKV_KEY_NAME"
echo ""

# Get current identity
echo "=== Current Azure Identity ==="
CURRENT_USER=$(az account show --query user.name -o tsv)
CURRENT_SP=$(az account show --query user.type -o tsv)
echo "Current user/identity: $CURRENT_USER ($CURRENT_SP)"
echo ""

# Get access token
echo "=== Getting Access Token ==="
TOKEN=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)
if [ -z "$TOKEN" ]; then
    echo "ERROR: Failed to get access token"
    exit 1
fi
echo "✓ Access token obtained"
echo ""

# Try to get key URL from certificate
echo "=== Attempting to get key from certificate ==="
if KEY_URL=$(az keyvault certificate show \
    --vault-name $AKV_VAULT_NAME \
    --name $AKV_KEY_NAME \
    --query "kid" \
    --output tsv 2>/dev/null); then
    echo "✓ Successfully got key URL from certificate: $KEY_URL"
    AKV_URL=$KEY_URL
elif KEY_URL=$(az keyvault key show \
    --vault-name $AKV_VAULT_NAME \
    --name $AKV_KEY_NAME \
    --query key.kid \
    --output tsv 2>/dev/null); then
    echo "✓ Successfully got key URL from key: $KEY_URL"
    AKV_URL=$KEY_URL
else
    echo "✗ ERROR: Failed to get key URL"
    echo "  - Certificate '$AKV_KEY_NAME' not found, or"
    echo "  - Key '$AKV_KEY_NAME' not found, or"
    echo "  - No permissions to read from vault"
    exit 1
fi
echo ""

# Check role assignments on the Key Vault
echo "=== Checking Role Assignments on Key Vault ==="
VAULT_SCOPE="/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$(az keyvault show --name $AKV_VAULT_NAME --query resourceGroup -o tsv)/providers/Microsoft.KeyVault/vaults/$AKV_VAULT_NAME"

if [ "$CURRENT_SP" == "servicePrincipal" ]; then
    CURRENT_ID=$(az account show --query user.name -o tsv)
    echo "Checking role assignments for service principal: $CURRENT_ID"
    echo "Scope: $VAULT_SCOPE"
    echo ""
    
    ROLES=$(az role assignment list \
        --assignee "$CURRENT_ID" \
        --scope "$VAULT_SCOPE" \
        --query "[].roleDefinitionName" \
        -o tsv 2>/dev/null || echo "")
    
    if [ -z "$ROLES" ]; then
        echo "✗ WARNING: No role assignments found at Key Vault scope"
        echo "  Roles may be assigned at subscription or resource group level"
        echo "  For Key Vault operations, roles should be assigned at the Key Vault resource level"
    else
        echo "✓ Found role assignments:"
        echo "$ROLES" | while read role; do
            echo "  - $role"
        done
    fi
else
    echo "Current identity is a user, checking role assignments..."
    CURRENT_ID=$(az account show --query user.name -o tsv)
    ROLES=$(az role assignment list \
        --assignee "$CURRENT_ID" \
        --scope "$VAULT_SCOPE" \
        --query "[].roleDefinitionName" \
        -o tsv 2>/dev/null || echo "")
    
    if [ -z "$ROLES" ]; then
        echo "✗ WARNING: No role assignments found at Key Vault scope"
    else
        echo "✓ Found role assignments:"
        echo "$ROLES" | while read role; do
            echo "  - $role"
        done
    fi
fi
echo ""

# Test signing operation
echo "=== Testing Sign Operation ==="
TEST_PAYLOAD='{"alg": "ES384", "value": "AQIDBAUGBwgJCgECAwQFBgcICQoBAgMEBQYHCAkKAQIDBAUGBwgJCgECAwQFBgcI"}'

HTTP_CODE=$(curl -s -o /tmp/sign_response.json -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    "${AKV_URL}/sign?api-version=7.2" \
    -d "$TEST_PAYLOAD")

if [ "$HTTP_CODE" == "200" ]; then
    echo "✓ Sign operation successful (HTTP $HTTP_CODE)"
    echo "Response: $(cat /tmp/sign_response.json | jq -c .)"
elif [ "$HTTP_CODE" == "401" ]; then
    echo "✗ ERROR: Sign operation failed with 401 Unauthorized"
    echo "  This indicates the identity lacks 'sign' permission on the key"
    echo "  Response: $(cat /tmp/sign_response.json 2>/dev/null || echo 'No response body')"
    echo ""
    echo "SOLUTION: Ensure the identity has 'Key Vault Crypto User' role"
    echo "  assigned at the Key Vault resource scope:"
    echo "  az role assignment create \\"
    echo "    --role 'Key Vault Crypto User' \\"
    echo "    --assignee <identity-id> \\"
    echo "    --scope '$VAULT_SCOPE'"
    exit 1
elif [ "$HTTP_CODE" == "403" ]; then
    echo "✗ ERROR: Sign operation failed with 403 Forbidden"
    echo "  This indicates the identity lacks permission"
    echo "  Response: $(cat /tmp/sign_response.json 2>/dev/null || echo 'No response body')"
    exit 1
else
    echo "✗ ERROR: Sign operation failed with HTTP $HTTP_CODE"
    echo "  Response: $(cat /tmp/sign_response.json 2>/dev/null || echo 'No response body')"
    exit 1
fi

rm -f /tmp/sign_response.json

echo ""
echo "=== All Checks Passed ==="
echo "The identity has the necessary permissions to sign with the key."

