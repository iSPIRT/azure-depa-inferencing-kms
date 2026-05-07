# Testing Strategy

## Table of Contents

- [Introduction](#introduction)
- [Unit Testing](#unit-testing)
- [System Tests](#system-tests)
- [End to End Testing](#end-to-end-testing)

## Introduction

The purpose of this document is to describe how the application is being tested to assure quality and coverage.

The application testing strategy depends on two main types of testing to achieve the objective:

- Unit testing
- System tests
- End to end (e2e) testing

## Unit Testing

This type of testing covers main KMS functions.

The application is using the [`Jest Testing Framework`](https://jestjs.io/docs/getting-started) to define the unit-test scenarios.

### Build and run unit-test using jest framework

```bash
# In the terminal window
make unit-test
```


**NOTE**: To enable the CCF functionality on testing environment, the application is using built-in feature of CCF, [the Polyfill implementation](https://microsoft.github.io/CCF/main/js/ccf-app/modules/polyfill.html) which overrides the CCF modules' implementation to support testing and local environments

## System Tests

System tests involve testing the application's workflow from beginning to end. This method aims to replicate real user scenarios to validate the system for integration and data integrity.

The system test is based on [pytest](https://docs.pytest.org/en/stable/).

All system tests are ran in docker to assure a clean testing environment deployed with CCF.

### How to run system tests

```bash
# In the terminal window
make test-system
```

### Running system tests against ACL (Azure Confidential Ledger)

Tests can run against a CCF network backed by Azure Confidential Ledger (ACL) instead of the local sandbox. Use this for pre-production validation.

#### Option 1: GitHub Actions (recommended)

1. **Trigger the system test workflow**
   In the repo: **Actions** → **System Test** → **Run workflow**.

2. **Inputs**
   - **test_path**: Test file name without `.py`, e.g. `test_keyRotationPolicy` for the key rotation tests, or `test_all_seq` for the full sequence.
   - **env**: `acl`
   - **use_akv**: `false` (or `true` if testing with AKV)

3. **Environment**
   The workflow uses the **UAT** environment and needs Azure secrets: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`. The job runs `scripts/ccf/acl/up.sh`, which creates or reuses an ACL ledger and sets `KMS_URL`, `WORKSPACE`, and cert paths.

4. **Run the key rotation tests against ACL**
   Set **test_path** to `test_keyRotationPolicy` to run all key rotation tests, including `test_key_rotation_public_key_exposure_delay`.

#### Option 2: Local run against an existing ACL deployment

1. **Prerequisites**
   - Azure CLI installed and logged in (`az login`).
   - A `.env` in the repo root with at least:
     - `SUBSCRIPTION` – Azure subscription ID
     - `RESOURCE_GROUP` – Resource group for the ledger
   - Optional: `DEPLOYMENT_NAME` – Ledger name (otherwise you’ll be prompted).

2. **Load ACL workspace and env**
   ```bash
   cd /path/to/azure-depa-inferencing-kms
   source scripts/ccf/acl/up.sh
   # Or, if you already have a workspace and only need env:
   # export KMS_WORKSPACE=~/$DEPLOYMENT_NAME.aclworkspace
   # export KMS_URL="https://$DEPLOYMENT_NAME.confidential-ledger.azure.com"
   # (and other KMS_* / WORKSPACE vars from the script output)
   ```

3. **Install Python deps and run the key rotation test**
   ```bash
   pip install -r requirements.txt
   TEST_ENVIRONMENT=ccf/acl pytest -sv test/system-test/test_keyRotationPolicy.py
   ```
   For only the public-key exposure delay test:
   ```bash
   TEST_ENVIRONMENT=ccf/acl pytest -sv test/system-test/test_keyRotationPolicy.py -k test_key_rotation_public_key_exposure_delay
   ```

4. **Notes**
   - `scripts/ccf/acl/up.sh` prints a JSON block with `DEPLOYMENT_NAME`, `WORKSPACE`, `KMS_URL`, and cert paths; the test `conftest` uses these via `call_script` and updated `os.environ`.
   - On ACL, governance uses member certs (e.g. `member0`); `key_rotation_policy_set.sh` does not switch to `user0` when `KMS_URL` is not localhost, so it uses the current member (correct for ACL).
   - **One ACL per session for key rotation tests:** `test_keyRotationPolicy.py` uses the session-scoped fixture `setup_kms_session` (like `test_all_seq.py`), so one Azure Confidential Ledger is created per test run and reused by all tests in that file.

## End to end testing

E2e testing is designed to quickly test if all endpoints are functional. This test run quickly and is intended to do a quick test after changes.

This can also be used to launch KMS. Next one can do manual curl tests to test the endpoints.

### How to run e2e tests

```bash
# In the terminal window
make demo
```
