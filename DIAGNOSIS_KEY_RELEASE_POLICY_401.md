# Diagnosis: 401 Error When Setting Key Release Policy

## Problem
The workflow fails with a 401 (Unauthorized) error when trying to sign a proposal using Azure Key Vault (AKV).

## Root Cause
The managed identity or service principal being used doesn't have the necessary **Key Vault permissions** to sign with the key.

## Error Location
The error occurs in `scripts/ccf/sign.sh` when making a POST request to:
```
${AKV_URL}/sign?api-version=7.2
```

Where `AKV_URL` is obtained from:
```bash
az keyvault key show --vault-name $AKV_VAULT_NAME --name $AKV_KEY_NAME --query key.kid
```

## Required Permissions

The managed identity/service principal needs the following **Key Vault Key permissions**:

1. **`sign`** - Required to sign data with the key
2. **`get`** - Required to retrieve key information (used by `az keyvault key show`)

## Solution Steps

### 1. Verify Role Assignment Scope (IMPORTANT)

**The roles must be assigned at the Key Vault resource level, not at subscription or resource group level.**

If you see roles assigned but they show "This resource" with "None", they may be assigned at the wrong scope.

Check current role assignments:
```bash
AKV_VAULT_NAME="<your-key-vault-name>"
CLIENT_ID="<managed-identity-client-id>"  # From AZURE_CLIENT_ID secret

# Get the Key Vault resource scope
VAULT_SCOPE="/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$(az keyvault show --name $AKV_VAULT_NAME --query resourceGroup -o tsv)/providers/Microsoft.KeyVault/vaults/$AKV_VAULT_NAME"

# Check role assignments at Key Vault scope
az role assignment list \
  --assignee $CLIENT_ID \
  --scope "$VAULT_SCOPE" \
  --query "[].{Role:roleDefinitionName, Scope:scope}" \
  -o table
```

### 2. Assign Roles at Correct Scope

If roles are missing or at wrong scope, assign them at the **Key Vault resource level**:

```bash
# Set variables
AKV_VAULT_NAME="<your-key-vault-name>"
CLIENT_ID="<managed-identity-client-id>"  # From AZURE_CLIENT_ID secret

# Get the Key Vault resource scope
VAULT_SCOPE="/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$(az keyvault show --name $AKV_VAULT_NAME --query resourceGroup -o tsv)/providers/Microsoft.KeyVault/vaults/$AKV_VAULT_NAME"

# Assign Key Vault Crypto User role (includes sign permission)
az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee $CLIENT_ID \
  --scope "$VAULT_SCOPE"

# Also assign Key Vault Certificates Officer if needed
az role assignment create \
  --role "Key Vault Certificates Officer" \
  --assignee $CLIENT_ID \
  --scope "$VAULT_SCOPE"
```

### 3. Alternative: Use Access Policies (Legacy)

If your Key Vault uses access policies instead of RBAC:

```bash
AKV_VAULT_NAME="<your-key-vault-name>"
CLIENT_ID="<managed-identity-client-id>"

# Grant 'sign' and 'get' permissions
az keyvault set-policy \
  --name $AKV_VAULT_NAME \
  --object-id $(az ad sp show --id $CLIENT_ID --query id -o tsv) \
  --key-permissions sign get
```

### 3. Verify Permissions

Test if the identity can sign:

```bash
# Get access token
TOKEN=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)

# Get key URL
KEY_URL=$(az keyvault key show \
  --vault-name $AKV_VAULT_NAME \
  --name $AKV_KEY_NAME \
  --query key.kid -o tsv)

# Test signing (this should return 200, not 401)
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "${KEY_URL}/sign?api-version=7.2" \
  -d '{"alg": "ES384", "value": "AQIDBAUGBwgJCgECAwQFBgcICQoBAgMEBQYHCAkKAQIDBAUGBwgJCgECAwQFBgcI"}'
```

### 4. Alternative: Use Access Policy vs RBAC

If using **Azure RBAC** (Role-Based Access Control) instead of access policies:

```bash
# Assign "Key Vault Crypto User" role (includes sign permission)
az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee $CLIENT_ID \
  --scope "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.KeyVault/vaults/$AKV_VAULT_NAME"
```

## Verification Checklist

- [ ] Managed identity has `sign` permission on the Key Vault key
- [ ] Managed identity has `get` permission on the Key Vault key
- [ ] The `AKV_VAULT_NAME` environment variable is set correctly
- [ ] The `AKV_KEY_NAME` environment variable is set correctly
- [ ] The `USE_AKV=true` environment variable is set
- [ ] The access token is being obtained for the correct resource (`https://vault.azure.net`)

## Additional Debugging

### Use Diagnostic Script

A diagnostic script is available to verify the setup:

```bash
export AKV_VAULT_NAME="<your-key-vault-name>"
export AKV_KEY_NAME="<your-key-or-certificate-name>"
./scripts/diagnose_akv_permissions.sh
```

This script will:
- Verify access token can be obtained
- Check if the key/certificate exists and can be accessed
- Verify role assignments at the correct scope
- Test the sign operation

### Manual Checks

If the issue persists, check:

1. **Role Assignment Scope**: Most common issue - roles assigned at subscription/resource group instead of Key Vault
   ```bash
   # Check assignments at Key Vault scope
   VAULT_SCOPE="/subscriptions/.../vaults/$AKV_VAULT_NAME"
   az role assignment list --scope "$VAULT_SCOPE" --assignee $CLIENT_ID
   ```

2. **Key/Certificate Name**: The script now tries both certificate and key lookups. Verify the name:
   ```bash
   # Try certificate
   az keyvault certificate show --vault-name $AKV_VAULT_NAME --name $AKV_KEY_NAME
   
   # Try key
   az keyvault key show --vault-name $AKV_VAULT_NAME --name $AKV_KEY_NAME
   ```

3. **Token validity**: The token might be expired or for the wrong resource
   ```bash
   TOKEN=$(az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)
   echo "Token length: ${#TOKEN}"  # Should be > 0
   ```

4. **Key Vault Access Model**: Verify if using RBAC or Access Policies
   ```bash
   az keyvault show --name $AKV_VAULT_NAME --query properties.enableRbacAuthorization
   # Should be true for RBAC, false for Access Policies
   ```

5. **Network access**: Ensure the GitHub Actions runner can reach Azure Key Vault
6. **Key type**: Verify the key supports signing operations (ES384, ES256, etc.)

## Related Files
- `scripts/ccf/sign.sh` - Signing script that uses AKV
- `scripts/kms/release_policy_set.sh` - Script that calls the signing function
- `scripts/kms/endpoints/proposals.sh` - Endpoint for submitting proposals

