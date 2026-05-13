import base64
import subprocess
from types import SimpleNamespace

import pytest

from src.crypto.service import AwsCredentials, CryptoService, DataKey, KmsClient, NitroKmsClient, MockKmsClient


CREDS = AwsCredentials(
    access_key_id="AKIA_TEST",
    secret_access_key="secret",
    session_token="token",
)


def test_nitro_kms_decrypts_data_key_with_kmstool(monkeypatch):
    expected_key = b"K" * 32
    captured_args = []

    def fake_run(args, **kwargs):
        captured_args.extend(args)
        assert kwargs["timeout"] == 45
        return SimpleNamespace(
            returncode=0,
            stdout=f"PLAINTEXT: {base64.b64encode(expected_key).decode()}\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    client = NitroKmsClient(region="us-east-1", tool_path="/kmstool", proxy_port=8000)

    data_key = client.decrypt_data_key(
        encrypted_key=b"kms-ciphertext",
        key_id="arn:aws:kms:us-east-1:111122223333:key/test",
        credentials=CREDS,
    )

    assert data_key == expected_key
    assert captured_args[:10] == [
        "/kmstool",
        "decrypt",
        "--region",
        "us-east-1",
        "--proxy-port",
        "8000",
        "--aws-access-key-id",
        "AKIA_TEST",
        "--aws-secret-access-key",
        "secret",
    ]
    assert "--ciphertext" in captured_args
    assert "--key-id" not in captured_args


def test_nitro_kms_generates_data_key_with_kmstool(monkeypatch):
    plaintext = b"P" * 32
    ciphertext = b"wrapped"

    def fake_run(args, **kwargs):
        assert args[1] == "genkey"
        assert args[-4:] == ["--key-id", "alias/medseal", "--key-spec", "AES-256"]
        return SimpleNamespace(
            returncode=0,
            stdout=(
                f"CIPHERTEXT: {base64.b64encode(ciphertext).decode()}\n"
                f"PLAINTEXT: {base64.b64encode(plaintext).decode()}\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    data_key = NitroKmsClient(tool_path="/kmstool").generate_data_key(
        "alias/medseal",
        credentials=CREDS,
    )

    assert data_key.plaintext == plaintext
    assert data_key.ciphertext == ciphertext
    assert data_key.key_id == "alias/medseal"


def test_nitro_kms_passes_canonical_encryption_context_to_kmstool(monkeypatch):
    plaintext = b"P" * 32
    ciphertext = b"wrapped"
    captured_args = []

    def fake_run(args, **kwargs):
        captured_args.extend(args)
        return SimpleNamespace(
            returncode=0,
            stdout=(
                f"CIPHERTEXT: {base64.b64encode(ciphertext).decode()}\n"
                f"PLAINTEXT: {base64.b64encode(plaintext).decode()}\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    NitroKmsClient(tool_path="/kmstool").generate_data_key(
        "alias/medseal",
        encryption_context={"principal": "arn:aws:iam::111122223333:user/alice", "jobId": "job-1"},
        credentials=CREDS,
    )

    context_index = captured_args.index("--encryption-context")
    assert captured_args[context_index + 1] == (
        '{"jobId":"job-1","principal":"arn:aws:iam::111122223333:user/alice"}'
    )


def test_mock_kms_binds_wrapped_key_to_encryption_context():
    kms = MockKmsClient()
    context = {"jobId": "job-1", "principal": "principal-a"}
    wrong_context = {"jobId": "job-2", "principal": "principal-a"}

    data_key = kms.generate_data_key("alias/medseal", encryption_context=context)

    assert kms.decrypt_data_key(
        data_key.ciphertext,
        "alias/medseal",
        encryption_context=context,
    ) == data_key.plaintext

    with pytest.raises(Exception):
        kms.decrypt_data_key(
            data_key.ciphertext,
            "alias/medseal",
            encryption_context=wrong_context,
        )


def test_crypto_service_rejects_context_mismatch():
    crypto = CryptoService(MockKmsClient())
    context = {"jobId": "job-1", "principal": "principal-a"}
    wrong_context = {"jobId": "job-2", "principal": "principal-a"}

    ciphertext, encrypted_key, iv, tag = crypto.encrypt_result(
        b"processed result",
        "alias/medseal",
        encryption_context=context,
    )

    assert crypto.decrypt_payload(
        ciphertext,
        encrypted_key,
        iv,
        tag,
        "alias/medseal",
        encryption_context=context,
    ) == b"processed result"

    with pytest.raises(Exception):
        crypto.decrypt_payload(
            ciphertext,
            encrypted_key,
            iv,
            tag,
            "alias/medseal",
            encryption_context=wrong_context,
        )


def test_crypto_service_aes_gcm_rejects_context_mismatch_when_kms_allows_key():
    crypto = CryptoService(ContextBlindKmsClient())
    context = {"jobId": "job-1", "principal": "principal-a"}
    wrong_context = {"jobId": "job-2", "principal": "principal-a"}

    ciphertext, encrypted_key, iv, tag = crypto.encrypt_result(
        b"processed result",
        "alias/medseal",
        encryption_context=context,
    )

    with pytest.raises(ValueError, match="Decryption failed"):
        crypto.decrypt_payload(
            ciphertext,
            encrypted_key,
            iv,
            tag,
            "alias/medseal",
            encryption_context=wrong_context,
        )


def test_nitro_kms_requires_credentials():
    with pytest.raises(ValueError, match="AWS credentials are required"):
        NitroKmsClient(tool_path="/kmstool").decrypt_data_key(
            encrypted_key=b"kms-ciphertext",
            key_id="alias/medseal",
        )


def test_nitro_kms_connectivity_is_kmstool_invocability(monkeypatch, tmp_path):
    tool = tmp_path / "kmstool"
    tool.write_text("")

    def fake_run(args, **kwargs):
        assert args == [str(tool), "decrypt", "--help"]
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="usage: kmstool_enclave_cli decrypt [options]\n\n Options:\n",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert NitroKmsClient(tool_path=str(tool)).check_connectivity("alias/medseal")


class ContextBlindKmsClient(KmsClient):
    def __init__(self):
        self._data_key = b"K" * 32

    def generate_data_key(self, key_id, encryption_context=None, credentials=None):
        del encryption_context, credentials
        return DataKey(
            plaintext=self._data_key,
            ciphertext=f"wrapped:{key_id}".encode(),
            key_id=key_id,
        )

    def decrypt_data_key(
        self,
        encrypted_key,
        key_id,
        encryption_context=None,
        attestation_document=None,
        recipient_private_key=None,
        credentials=None,
    ):
        del encrypted_key, key_id, encryption_context, attestation_document, recipient_private_key, credentials
        return self._data_key

    def check_connectivity(self, key_id):
        del key_id
        return True
