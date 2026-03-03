import json
import os
import pytest
import time
from endpoints import key, refresh, pubkey
from utils import (
    apply_settings_policy,
    apply_key_release_policy,
    apply_key_rotation_policy,
    get_test_attestation,
    get_test_public_wrapping_key,
    decrypted_wrapped_key,
    call_endpoint,
)


# Test the key retrieval during the grace period with key rotation policy.
def test_key_in_grace_period_with_rotation_policy(setup_kms_session):
    policy = {
        "service": {
            "name": "custom-kms",
            "description": "Custom Key Management Service",
            "version": "2.0.0",
            "debug": True,
        }
    }
    apply_settings_policy(policy)
    apply_key_release_policy()
    apply_key_rotation_policy()
    refresh()
    while True:
        status_code, key_json = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
        )
        if status_code != 202:
            break
    assert status_code == 200

    # unwrap key
    status_code, unwrapped_json = call_endpoint(fr"""
        scripts/kms/endpoints/unwrapKey.sh \
            --attestation "$(cat test/attestation-samples/snp.json)" \
            --wrapping-key-file test/data-samples/publicWrapKey.pem \
            --wrappedKid "{key_json["wrappedKid"]}"
    """)
    assert status_code == 200
    unwrapped = decrypted_wrapped_key(unwrapped_json["wrapped"])
    unwrapped_json = json.loads(unwrapped)
    print(unwrapped_json)
    assert unwrapped_json["kty"] == "OKP"
    assert unwrapped_json.get("expiry") is not None

# Test the key retrieval during the grace period without key rotation policy.
def test_key_in_grace_period_without_rotation_policy(setup_kms_session):
    apply_key_release_policy()
    refresh()
    while True:
        status_code, key_json = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
        )
        if status_code != 202:
            break
    assert status_code == 200

    # unwrap key
    status_code, unwrapped_json = call_endpoint(fr"""
        scripts/kms/endpoints/unwrapKey.sh \
            --attestation "$(cat test/attestation-samples/snp.json)" \
            --wrapping-key-file test/data-samples/publicWrapKey.pem \
            --wrappedKid "{key_json["wrappedKid"]}"
    """)
    assert status_code == 200
    unwrapped = decrypted_wrapped_key(unwrapped_json["wrapped"])
    unwrapped_json = json.loads(unwrapped)
    print(unwrapped_json)
    assert unwrapped_json["kty"] == "OKP"
    assert unwrapped_json.get("expiry") is None

# Test the key retrieval during with custom key rotation policy.
def test_key_in_grace_period_with_custom_rotation_policy(setup_kms_session):
    apply_settings_policy()
    apply_key_release_policy()
    apply_key_rotation_policy()
    refresh()
    while True:
        status_code, key_json = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
        )
        if status_code != 202:
            break
    assert status_code == 200

    # unwrap key
    status_code, unwrapped_json = call_endpoint(fr"""
        scripts/kms/endpoints/unwrapKey.sh \
            --attestation "$(cat test/attestation-samples/snp.json)" \
            --wrapping-key-file test/data-samples/publicWrapKey.pem \
            --wrappedKid "{key_json["wrappedKid"]}"
    """)
    assert status_code == 200
    unwrapped = decrypted_wrapped_key(unwrapped_json["wrapped"])
    unwrapped_json = json.loads(unwrapped)
    assert unwrapped_json["kty"] == "OKP"
    assert unwrapped_json.get("expiry") is not None
    policy = {
        "actions": [
            {
                "name": "set_key_rotation_policy",
                "args": {
                    "key_rotation_policy": {
                        "rotation_interval_seconds": 10,
                        "grace_period_seconds": 5,
                    }
                },
            }
        ]
    }
    apply_key_rotation_policy(policy)
    status_code, unwrapped_json = call_endpoint(fr"""
        scripts/kms/endpoints/unwrapKey.sh \
            --attestation "$(cat test/attestation-samples/snp.json)" \
            --wrapping-key-file test/data-samples/publicWrapKey.pem \
            --wrappedKid "{key_json["wrappedKid"]}"
    """)
    assert status_code == 200

    # wait for the key to expire
    time.sleep(20)
    status_code, unwrapped_json = call_endpoint(fr"""
        scripts/kms/endpoints/unwrapKey.sh \
            --attestation "$(cat test/attestation-samples/snp.json)" \
            --wrapping-key-file test/data-samples/publicWrapKey.pem \
            --wrappedKid "{key_json["wrappedKid"]}"
    """)
    assert status_code == 410  # check for expired key


def test_key_rotation_public_key_exposure_delay(setup_kms_session):
    """Verify that after a refresh, public-key endpoints lag by grace_period_seconds
    (so private-key clients can cache first), while private-key endpoint gets new key immediately."""
    apply_settings_policy()
    apply_key_release_policy()
    # Short grace period (2s) so public key is only exposed 2s after key creation
    rotation_policy = {
        "actions": [
            {
                "name": "set_key_rotation_policy",
                "args": {
                    "key_rotation_policy": {
                        "rotation_interval_seconds": 3600,
                        "grace_period_seconds": 2,
                    }
                },
            }
        ]
    }
    apply_key_rotation_policy(rotation_policy)

    # Create first key
    refresh()
    while True:
        status_code, key_1_resp = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
        )
        if status_code != 202:
            break
    assert status_code == 200
    kid_1 = key_1_resp["wrappedKid"]
    assert kid_1.endswith("_1"), f"Expected kid to end with _1, got {kid_1}"

    while True:
        status_code, pubkey_1 = pubkey()
        if status_code != 202:
            break
    assert status_code == 200
    key_id_1 = pubkey_1["id"]
    assert key_id_1 == 11, f"Expected first key id 11, got {key_id_1}"

    # Create second key
    refresh()

    # Immediately: public-key endpoint should still return key 1 (grace period delay)
    while True:
        status_code, pubkey_after_refresh = pubkey()
        if status_code != 202:
            break
    assert status_code == 200
    assert pubkey_after_refresh["id"] == key_id_1, (
        f"Public key should still be key 1 (id {key_id_1}) before grace period, got id {pubkey_after_refresh.get('id')}"
    )

    # Private-key endpoint (no kid) should return new key immediately
    while True:
        status_code, key_2_resp = key(
            attestation=get_test_attestation(),
            wrapping_key=get_test_public_wrapping_key(),
        )
        if status_code != 202:
            break
    assert status_code == 200
    kid_2 = key_2_resp["wrappedKid"]
    assert kid_2.endswith("_2"), f"Expected new key kid to end with _2, got {kid_2}"

    # Wait for grace period to pass
    time.sleep(3)

    # Now public-key endpoint should return key 2
    while True:
        status_code, pubkey_after_grace = pubkey()
        if status_code != 202:
            break
    assert status_code == 200
    assert pubkey_after_grace["id"] == 12, (
        f"Public key should be key 2 (id 12) after grace period, got id {pubkey_after_grace.get('id')}"
    )


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-s"])
