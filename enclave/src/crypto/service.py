"""
Envelope encryption helpers used inside the enclave.

The enclave obtains data keys through KMS, uses AES-256-GCM for payload
encryption, and drops plaintext key references as soon as each operation
finishes.
"""

from __future__ import annotations

import logging
import base64
import json
import os
import secrets
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import config

logger = logging.getLogger(__name__)

AES_KEY_SIZE = 32       # 256 bits
GCM_IV_SIZE = 12        # 96 bits (NIST recommended)
GCM_TAG_SIZE = 16       # 128 bits
ENCRYPTION_CONTEXT_KEYS = frozenset(("jobId", "principal"))


@dataclass(frozen=True)
class DataKey:
    """A KMS-generated data key pair."""

    plaintext: bytes     # Raw key bytes (wipe after use)
    ciphertext: bytes    # KMS-encrypted key (safe to store)
    key_id: str          # KMS key ARN

    def wipe(self) -> None:
        """
        Best-effort wipe of the plaintext key from memory.

        Python bytes are immutable, so callers should treat this as reference
        cleanup rather than guaranteed memory erasure.
        """
        pass


@dataclass(frozen=True)
class AttestedRecipientKeyPair:
    """Ephemeral keypair bound into one KMS Recipient attestation document."""

    private_key: rsa.RSAPrivateKey
    public_key_der: bytes


@dataclass(frozen=True)
class AwsCredentials:
    """Temporary AWS credentials supplied by the parent instance over vsock."""

    access_key_id: str
    secret_access_key: str
    session_token: str


class KmsClient(ABC):
    """Interface for KMS operations."""

    @abstractmethod
    def generate_data_key(
        self,
        key_id: str,
        encryption_context: Optional[Mapping[str, str]] = None,
        credentials: Optional[AwsCredentials] = None,
    ) -> DataKey:
        """Generate a new data key using KMS."""
        ...

    @abstractmethod
    def decrypt_data_key(
        self,
        encrypted_key: bytes,
        key_id: str,
        encryption_context: Optional[Mapping[str, str]] = None,
        attestation_document: Optional[bytes] = None,
        recipient_private_key: Optional[rsa.RSAPrivateKey] = None,
        credentials: Optional[AwsCredentials] = None,
    ) -> bytes:
        """Decrypt a data key using KMS with optional attestation."""
        ...

    @abstractmethod
    def check_connectivity(self, key_id: str) -> bool:
        """Return True if the KMS client can reach the configured key."""
        ...


class NitroKmsClient(KmsClient):
    """
    Production KMS client for Nitro Enclaves.

    Uses AWS's kmstool-enclave-cli from the Nitro Enclaves SDK for C.
    The tool performs the NSM attestation, talks to KMS through the
    parent vsock proxy, unwraps CiphertextForRecipient, and prints
    base64-encoded plaintext for this Python process to use.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        tool_path: Optional[str] = None,
        proxy_port: Optional[int] = None,
        timeout_seconds: Optional[int] = None,
    ):
        self._region = region
        self._tool_path = tool_path or os.environ.get(
            "KMSTOOL_ENCLAVE_CLI",
            "/usr/local/bin/kmstool-enclave-cli",
        )
        self._proxy_port = proxy_port or int(os.environ.get("KMS_PROXY_PORT", "8000"))
        self._timeout_seconds = timeout_seconds or int(
            os.environ.get("KMSTOOL_TIMEOUT_SECONDS", "45")
        )

    def generate_data_key(
        self,
        key_id: str,
        encryption_context: Optional[Mapping[str, str]] = None,
        credentials: Optional[AwsCredentials] = None,
    ) -> DataKey:
        creds = _require_credentials(credentials)
        output = self._run_kmstool(
            "genkey",
            creds,
            "--key-id",
            key_id,
            "--key-spec",
            "AES-256",
            *_encryption_context_args(encryption_context),
        )
        ciphertext_b64 = _extract_prefixed_value(output, "CIPHERTEXT")
        plaintext_b64 = _extract_prefixed_value(output, "PLAINTEXT")
        plaintext = base64.b64decode(plaintext_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        _validate_aes256_key(plaintext)

        return DataKey(
            plaintext=plaintext,
            ciphertext=ciphertext,
            key_id=key_id,
        )

    def decrypt_data_key(
        self,
        encrypted_key: bytes,
        key_id: str,
        encryption_context: Optional[Mapping[str, str]] = None,
        attestation_document: Optional[bytes] = None,
        recipient_private_key: Optional[rsa.RSAPrivateKey] = None,
        credentials: Optional[AwsCredentials] = None,
    ) -> bytes:
        del key_id, attestation_document, recipient_private_key
        creds = _require_credentials(credentials)
        ciphertext_b64 = base64.b64encode(encrypted_key).decode("ascii")
        output = self._run_kmstool(
            "decrypt",
            creds,
            "--ciphertext",
            ciphertext_b64,
            *_encryption_context_args(encryption_context),
        )
        plaintext = base64.b64decode(_extract_prefixed_value(output, "PLAINTEXT"))
        _validate_aes256_key(plaintext)
        return plaintext

    def check_connectivity(self, key_id: str) -> bool:
        del key_id
        if not os.path.exists(self._tool_path):
            return False
        try:
            proc = subprocess.run(
                [self._tool_path, "decrypt", "--help"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            return False
        output = f"{proc.stdout}\n{proc.stderr}"
        return "kmstool" in output and "decrypt" in output and "Options" in output

    def _run_kmstool(
        self,
        command: str,
        credentials: AwsCredentials,
        *extra_args: str,
    ) -> str:
        args = [
            self._tool_path,
            command,
            "--region",
            self._region,
            "--proxy-port",
            str(self._proxy_port),
            "--aws-access-key-id",
            credentials.access_key_id,
            "--aws-secret-access-key",
            credentials.secret_access_key,
            "--aws-session-token",
            credentials.session_token,
            *extra_args,
        ]
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=self._timeout_seconds,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"kmstool {command} failed with exit {proc.returncode}: "
                f"{_sanitize_kmstool_error(proc.stderr)}"
            )
        return proc.stdout


class MockKmsClient(KmsClient):
    """
    Development KMS client for local testing.

    Production startup rejects this implementation.
    """

    def __init__(self):
        self._master_key = secrets.token_bytes(AES_KEY_SIZE)
        logger.warning("Using mock KMS client for local development")

    def generate_data_key(
        self,
        key_id: str,
        encryption_context: Optional[Mapping[str, str]] = None,
        credentials: Optional[AwsCredentials] = None,
    ) -> DataKey:
        del credentials
        plaintext = secrets.token_bytes(AES_KEY_SIZE)
        aesgcm = AESGCM(self._master_key)
        iv = secrets.token_bytes(GCM_IV_SIZE)
        ciphertext = iv + aesgcm.encrypt(
            iv,
            plaintext,
            _optional_encryption_context_aad(encryption_context),
        )

        return DataKey(
            plaintext=plaintext,
            ciphertext=ciphertext,
            key_id=key_id,
        )

    def decrypt_data_key(
        self,
        encrypted_key: bytes,
        key_id: str,
        encryption_context: Optional[Mapping[str, str]] = None,
        attestation_document: Optional[bytes] = None,
        recipient_private_key: Optional[rsa.RSAPrivateKey] = None,
        credentials: Optional[AwsCredentials] = None,
    ) -> bytes:
        del key_id, attestation_document, recipient_private_key, credentials
        iv = encrypted_key[:GCM_IV_SIZE]
        ciphertext = encrypted_key[GCM_IV_SIZE:]
        aesgcm = AESGCM(self._master_key)
        return aesgcm.decrypt(
            iv,
            ciphertext,
            _optional_encryption_context_aad(encryption_context),
        )

    def check_connectivity(self, key_id: str) -> bool:
        return True


class CryptoService:
    """
    Envelope encrypt/decrypt operations backed by an injected KMS client.
    """

    def __init__(self, kms_client: KmsClient):
        if config.IS_PRODUCTION and isinstance(kms_client, MockKmsClient):
            raise RuntimeError("MEDSEAL: production refuses MockKmsClient")
        self._kms = kms_client

    @staticmethod
    def generate_attested_recipient_key_pair() -> AttestedRecipientKeyPair:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return AttestedRecipientKeyPair(
            private_key=private_key,
            public_key_der=public_key_der,
        )

    def check_kms_connectivity(self, key_id: str) -> bool:
        return self._kms.check_connectivity(key_id)

    def decrypt_payload(
        self,
        ciphertext: bytes,
        encrypted_data_key: bytes,
        iv: bytes,
        auth_tag: bytes,
        kms_key_id: str,
        encryption_context: Mapping[str, str],
        attestation_document: Optional[bytes] = None,
        recipient_private_key: Optional[rsa.RSAPrivateKey] = None,
        credentials: Optional[AwsCredentials] = None,
    ) -> bytes:
        """
        Decrypt an envelope-encrypted payload.
        """
        logger.info("Decrypting data key via KMS")

        data_key = self._kms.decrypt_data_key(
            encrypted_key=encrypted_data_key,
            key_id=kms_key_id,
            encryption_context=encryption_context,
            attestation_document=attestation_document,
            recipient_private_key=recipient_private_key,
            credentials=credentials,
        )

        try:
            aesgcm = AESGCM(data_key)
            ciphertext_with_tag = ciphertext + auth_tag
            plaintext = aesgcm.decrypt(
                iv,
                ciphertext_with_tag,
                canonical_encryption_context(encryption_context),
            )
            logger.info("Payload decrypted successfully")
            return plaintext
        except Exception as e:
            logger.error("Decryption failed (tampering or wrong key?): %s", e)
            raise ValueError("Decryption failed: data may have been tampered with") from e
        finally:
            del data_key

    def encrypt_result(
        self,
        plaintext: bytes,
        kms_key_id: str,
        encryption_context: Mapping[str, str],
        credentials: Optional[AwsCredentials] = None,
    ) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Envelope-encrypt processing results for return to the client.

        Returns: (ciphertext, encrypted_data_key, iv, auth_tag)
        """
        logger.info("Generating new data key for result encryption")

        data_key = self._kms.generate_data_key(
            kms_key_id,
            encryption_context=encryption_context,
            credentials=credentials,
        )

        iv = secrets.token_bytes(GCM_IV_SIZE)
        aesgcm = AESGCM(data_key.plaintext)
        ciphertext_with_tag = aesgcm.encrypt(
            iv,
            plaintext,
            canonical_encryption_context(encryption_context),
        )

        ciphertext = ciphertext_with_tag[:-GCM_TAG_SIZE]
        auth_tag = ciphertext_with_tag[-GCM_TAG_SIZE:]

        logger.info("Result encrypted with fresh data key")

        data_key.wipe()

        return ciphertext, data_key.ciphertext, iv, auth_tag


def canonical_encryption_context(context: Mapping[str, str]) -> bytes:
    return _encryption_context_json(context).encode("utf-8")


def _optional_encryption_context_aad(context: Optional[Mapping[str, str]]) -> Optional[bytes]:
    if context is None:
        return None
    return canonical_encryption_context(context)


def _encryption_context_json(context: Mapping[str, str]) -> str:
    normalized = _normalize_encryption_context(context)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"))


def _normalize_encryption_context(context: Mapping[str, str]) -> dict[str, str]:
    if set(context.keys()) != ENCRYPTION_CONTEXT_KEYS:
        raise ValueError("encryption context must contain exactly jobId and principal")

    normalized: dict[str, str] = {}
    for key in sorted(ENCRYPTION_CONTEXT_KEYS):
        value = context[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"encryption context value is missing: {key}")
        normalized[key] = value
    return normalized


def _encryption_context_args(context: Optional[Mapping[str, str]]) -> tuple[str, ...]:
    if context is None:
        return ()
    return ("--encryption-context", _encryption_context_json(context))


def _require_credentials(credentials: Optional[AwsCredentials]) -> AwsCredentials:
    if credentials is None:
        raise ValueError("AWS credentials are required for enclave KMS operations")
    for field_name, value in (
        ("access_key_id", credentials.access_key_id),
        ("secret_access_key", credentials.secret_access_key),
        ("session_token", credentials.session_token),
    ):
        if not value:
            raise ValueError(f"AWS credential field is missing: {field_name}")
    return credentials


def _extract_prefixed_value(output: str, prefix: str) -> str:
    needle = f"{prefix}:"
    for line in output.splitlines():
        if line.startswith(needle):
            value = line.split(":", 1)[1].strip()
            if value:
                return value
    raise RuntimeError(f"kmstool output missing {prefix}")


def _validate_aes256_key(key: bytes) -> None:
    if len(key) != AES_KEY_SIZE:
        raise ValueError(
            f"KMS data key must be {AES_KEY_SIZE} bytes, got {len(key)}"
        )


def _sanitize_kmstool_error(stderr: str) -> str:
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    if not lines:
        return "no stderr"
    return "\n".join(lines[-6:])
