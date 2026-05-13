import base64
import sys
from types import SimpleNamespace

import pytest

from medseal_cli import EnvelopeEncryptor, MedSealClient, principal_from_bearer_token


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self):
        self.headers = {}
        self.process_payload = None

    def post(self, url, json, timeout):
        if url.endswith("/api/v1/process"):
            self.process_payload = json
            return FakeResponse({"jobId": "job-1", "status": "SUBMITTED"})

        raise AssertionError(f"unexpected URL: {url}")


CONTEXT = {
    "jobId": "11111111-1111-4111-8111-111111111111",
    "principal": "arn:aws:iam::111122223333:user/tester",
}


class FakeKmsClient:
    def generate_data_key(self, KeyId, KeySpec, EncryptionContext):
        assert KeyId == "alias/medseal-master"
        assert KeySpec == "AES_256"
        assert EncryptionContext == CONTEXT
        return {
            "Plaintext": bytes(range(32)),
            "CiphertextBlob": b"kms-ciphertext-blob-" * 8,
        }

    def decrypt(self, CiphertextBlob, KeyId, EncryptionContext):
        assert KeyId == "alias/medseal-master"
        assert CiphertextBlob == b"kms-ciphertext-blob-" * 8
        assert EncryptionContext == CONTEXT
        return {"Plaintext": bytes(range(32))}


def test_cli_direct_kms_sends_ciphertext_blob_not_raw_key(monkeypatch):
    fake_session = FakeSession()
    monkeypatch.setattr("requests.Session", lambda: fake_session)
    monkeypatch.setitem(
        sys.modules,
        "boto3",
        SimpleNamespace(client=lambda service, region_name: FakeKmsClient() if service == "kms" else None),
    )
    monkeypatch.setenv("MEDSEAL_TOKEN", "test-token")

    client = MedSealClient("https://gateway.example")
    encryptor = EnvelopeEncryptor(region="us-east-1")
    data_key = encryptor.generate_data_key("alias/medseal-master", CONTEXT)
    encrypted = encryptor.encrypt(b"patient record", "alias/medseal-master", data_key, CONTEXT)
    client.submit(encrypted)

    sent_blob = base64.b64decode(fake_session.process_payload["encryptedDataKeyB64"])
    raw_key = base64.b64decode(data_key["plaintextB64"])

    assert fake_session.headers["Authorization"] == "Bearer test-token"
    assert sent_blob == base64.b64decode(data_key["ciphertextB64"])
    assert sent_blob != raw_key
    assert len(sent_blob) > 100
    assert len(raw_key) == 32
    assert fake_session.process_payload["jobId"] == CONTEXT["jobId"]
    assert fake_session.process_payload["principal"] == CONTEXT["principal"]
    assert fake_session.process_payload["encryptionContext"] == CONTEXT


def test_cli_aes_gcm_rejects_context_mismatch(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "boto3",
        SimpleNamespace(client=lambda service, region_name: FakeKmsClient() if service == "kms" else None),
    )
    encryptor = EnvelopeEncryptor(region="us-east-1")
    data_key = {
        "plaintextB64": base64.b64encode(bytes(range(32))).decode(),
        "ciphertextB64": base64.b64encode(b"kms-ciphertext-blob-" * 8).decode(),
    }
    encrypted = encryptor.encrypt(b"patient record", "alias/medseal-master", data_key, CONTEXT)
    encrypted_result = {
        "encryptedDataKeyB64": encrypted["encrypted_data_key_b64"],
        "encryptedResultB64": encrypted["ciphertext_b64"],
        "ivB64": encrypted["iv_b64"],
        "authTagB64": encrypted["auth_tag_b64"],
    }

    assert encryptor.decrypt(encrypted_result, "alias/medseal-master", CONTEXT) == b"patient record"

    with pytest.raises(Exception):
        encryptor.decrypt(
            encrypted_result,
            "alias/medseal-master",
            {**CONTEXT, "jobId": "22222222-2222-4222-8222-222222222222"},
        )


def test_cli_can_bind_context_to_jwt_principal():
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(
        b'{"sub":"doctor-123","email":"doctor@example.com"}'
    ).decode().rstrip("=")

    assert principal_from_bearer_token(f"{header}.{payload}.") == "doctor-123"
