#!/usr/bin/env python3
"""
MedSeal CLI: Command-line client for confidential medical data processing.

Encrypts medical records locally using envelope encryption (AES-256-GCM
with KMS-managed data keys), submits them to the MedSeal gateway, and
decrypts the results locally.

Usage:
    python medseal_cli.py encrypt-and-process --file patient_record.txt
    python medseal_cli.py status --job-id <job_id>
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
import uuid
from pathlib import Path

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_GATEWAY_URL = os.environ.get("MEDSEAL_GATEWAY_URL", "http://localhost:8080")
DEFAULT_KMS_KEY_ID = os.environ.get("MEDSEAL_KMS_KEY_ID", "alias/medseal-master")
DEFAULT_REGION = os.environ.get("AWS_REGION", "us-east-1")
DEFAULT_PRINCIPAL = os.environ.get("MEDSEAL_PRINCIPAL") or os.environ.get("MEDSEAL_DEV_PRINCIPAL")

GCM_IV_SIZE = 12
GCM_TAG_SIZE = 16


def canonical_encryption_context(context: dict[str, str]) -> bytes:
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")


def debug_tamper_job_context(encrypted_payload: dict) -> str:
    """Mutate a request after encryption so live diagnostics can prove context binding."""
    tampered_job_id = str(uuid.uuid4())
    while tampered_job_id == encrypted_payload["job_id"]:
        tampered_job_id = str(uuid.uuid4())

    encrypted_payload["job_id"] = tampered_job_id
    encrypted_payload["encryption_context"] = {
        **encrypted_payload["encryption_context"],
        "jobId": tampered_job_id,
    }
    return tampered_job_id


def principal_from_bearer_token(token: str | None = None) -> str | None:
    token = token or os.environ.get("MEDSEAL_TOKEN")
    if not token or token.count(".") < 2:
        return None

    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return None

    for claim in ("arn", "sub", "email"):
        value = payload.get(claim)
        if isinstance(value, str) and value.strip():
            return value
    return None


class EnvelopeEncryptor:
    """Client-side envelope encryption using KMS + AES-256-GCM."""

    def __init__(self, region: str = DEFAULT_REGION):
        self._region = region
        self._kms = None
        self._sts = None

    def encrypt(
            self,
            plaintext: bytes,
            kms_key_id: str,
            data_key_response: dict,
            encryption_context: dict[str, str]) -> dict:
        """
        Encrypt data and return the envelope fields expected by the gateway.
        """
        data_key = bytearray(base64.b64decode(data_key_response["plaintextB64"]))
        encrypted_data_key_b64 = data_key_response["ciphertextB64"]
        encrypted_data_key = base64.b64decode(encrypted_data_key_b64)
        if len(data_key) != 32:
            data_key[:] = b"\x00" * len(data_key)
            raise ValueError("Data key response contained an invalid AES-256 key")
        if len(encrypted_data_key) == 32:
            data_key[:] = b"\x00" * len(data_key)
            raise ValueError("Data key response contained a raw AES key instead of a KMS ciphertext blob")

        iv = secrets.token_bytes(GCM_IV_SIZE)
        try:
            aesgcm = AESGCM(data_key)
            ciphertext_with_tag = aesgcm.encrypt(
                iv,
                plaintext,
                canonical_encryption_context(encryption_context),
            )
        finally:
            data_key[:] = b"\x00" * len(data_key)

        ciphertext = ciphertext_with_tag[:-GCM_TAG_SIZE]
        auth_tag = ciphertext_with_tag[-GCM_TAG_SIZE:]

        return {
            "ciphertext_b64": base64.b64encode(ciphertext).decode(),
            "encrypted_data_key_b64": encrypted_data_key_b64,
            "iv_b64": base64.b64encode(iv).decode(),
            "auth_tag_b64": base64.b64encode(auth_tag).decode(),
            "kms_key_id": kms_key_id,
            "job_id": encryption_context["jobId"],
            "principal": encryption_context["principal"],
            "encryption_context": encryption_context,
        }

    def generate_data_key(self, kms_key_id: str, encryption_context: dict[str, str]) -> dict:
        """
        Generate a data key directly from AWS KMS.

        The plaintext key stays in the client process and is never returned by
        the MedSeal gateway. The gateway receives only the KMS ciphertext blob.
        """
        response = self._kms_client().generate_data_key(
            KeyId=kms_key_id,
            KeySpec="AES_256",
            EncryptionContext=encryption_context,
        )
        return {
            "plaintextB64": base64.b64encode(response["Plaintext"]).decode(),
            "ciphertextB64": base64.b64encode(response["CiphertextBlob"]).decode(),
        }

    def decrypt(
            self,
            encrypted_result: dict,
            kms_key_id: str,
            encryption_context: dict[str, str]) -> bytes:
        """Decrypt an envelope-encrypted result."""
        encrypted_data_key = base64.b64decode(encrypted_result["encryptedDataKeyB64"])
        ciphertext = base64.b64decode(encrypted_result["encryptedResultB64"])
        iv = base64.b64decode(encrypted_result["ivB64"])
        auth_tag = base64.b64decode(encrypted_result["authTagB64"])

        response = self._kms_client().decrypt(
            CiphertextBlob=encrypted_data_key,
            KeyId=kms_key_id,
            EncryptionContext=encryption_context,
        )
        data_key = response["Plaintext"]

        aesgcm = AESGCM(data_key)
        ciphertext_with_tag = ciphertext + auth_tag
        plaintext = aesgcm.decrypt(
            iv,
            ciphertext_with_tag,
            canonical_encryption_context(encryption_context),
        )

        del data_key
        return plaintext

    def caller_principal(self, override: str | None = None) -> str:
        """Resolve the authenticated principal used in the KMS encryption context."""
        if override:
            return override
        if DEFAULT_PRINCIPAL:
            return DEFAULT_PRINCIPAL
        token_principal = principal_from_bearer_token()
        if token_principal:
            return token_principal
        return self._sts_client().get_caller_identity()["Arn"]

    def _kms_client(self):
        if self._kms is None:
            import boto3

            self._kms = boto3.client("kms", region_name=self._region)
        return self._kms

    def _sts_client(self):
        if self._sts is None:
            import boto3

            self._sts = boto3.client("sts", region_name=self._region)
        return self._sts


class MedSealClient:
    """HTTP client for the MedSeal gateway API."""

    def __init__(self, gateway_url: str = DEFAULT_GATEWAY_URL, token: str | None = None):
        self._base_url = gateway_url.rstrip("/")
        self._session = requests.Session()
        bearer_token = token if token is not None else os.environ.get("MEDSEAL_TOKEN")
        if bearer_token:
            self._session.headers.update({"Authorization": f"Bearer {bearer_token}"})

    def submit(self, encrypted_payload: dict) -> dict:
        """Submit an encrypted record for processing."""
        response = self._session.post(
            f"{self._base_url}/api/v1/process",
            json={
                "ciphertextB64": encrypted_payload["ciphertext_b64"],
                "encryptedDataKeyB64": encrypted_payload["encrypted_data_key_b64"],
                "ivB64": encrypted_payload["iv_b64"],
                "authTagB64": encrypted_payload["auth_tag_b64"],
                "kmsKeyId": encrypted_payload["kms_key_id"],
                "jobId": encrypted_payload["job_id"],
                "principal": encrypted_payload["principal"],
                "encryptionContext": encrypted_payload["encryption_context"],
            },
            timeout=120,
        )
        response.raise_for_status()
        return response.json()

    def get_status(self, job_id: str) -> dict:
        """Get job status."""
        response = self._session.get(
            f"{self._base_url}/api/v1/jobs/{job_id}",
            timeout=10,
        )
        response.raise_for_status()
        return response.json()

    def get_result(self, job_id: str) -> bytes:
        """Retrieve encrypted result."""
        response = self._session.get(
            f"{self._base_url}/api/v1/jobs/{job_id}/result",
            timeout=30,
        )
        response.raise_for_status()
        return response.content

    def health(self) -> dict:
        """Check gateway health."""
        response = self._session.get(
            f"{self._base_url}/api/v1/health",
            timeout=5,
        )
        response.raise_for_status()
        return response.json()


def cmd_encrypt_and_process(args):
    """Encrypt a file and submit for processing."""
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    plaintext = file_path.read_bytes()
    print(f"Read {len(plaintext)} bytes from {file_path}")

    client = MedSealClient(args.gateway_url)
    encryptor = EnvelopeEncryptor(region=args.region)
    encryption_context = {
        "jobId": args.job_id or str(uuid.uuid4()),
        "principal": encryptor.caller_principal(args.principal),
    }

    print("Requesting KMS data key directly from AWS KMS...")
    data_key = encryptor.generate_data_key(args.kms_key_id, encryption_context)

    print("Encrypting with KMS envelope encryption...")
    encrypted = encryptor.encrypt(plaintext, args.kms_key_id, data_key, encryption_context)
    print(f"Encrypted: {len(encrypted['ciphertext_b64'])} bytes ciphertext (base64)")

    if args.debug_tamper_context:
        if os.environ.get("MEDSEAL_ENV") == "production":
            print("Error: --debug-tamper-context is disabled in production", file=sys.stderr)
            sys.exit(2)
        original_job_id = encrypted["job_id"]
        tampered_job_id = debug_tamper_job_context(encrypted)
        print(f"Debug: tampered jobId from {original_job_id} to {tampered_job_id}")

    print(f"Submitting to {args.gateway_url}...")
    result = client.submit(encrypted)

    job_id = result.get("jobId", "unknown")
    status = result.get("status", "unknown")
    print(f"Job ID: {job_id}")
    print(f"Status: {status}")

    if status == "COMPLETED":
        processing_time = result.get("processingTimeMs", 0)
        attestation_hash = result.get("attestationHash", "N/A")
        print(f"Processing time: {processing_time}ms")
        print(f"Attestation hash: {attestation_hash}")

        print("Decrypting result locally...")
        decrypted = encryptor.decrypt(
            result,
            args.kms_key_id,
            result.get("encryptionContext") or encrypted["encryption_context"],
        )
        output = json.loads(decrypted.decode("utf-8"))

        print("\n" + "=" * 60)
        print("DE-IDENTIFIED RECORD")
        print("=" * 60)
        print(output["deidentification"]["deidentified_text"])
        print(f"\nPHI entities removed: {output['deidentification']['entity_count']}")

        print("\n" + "=" * 60)
        print("ICD-10 CLASSIFICATION")
        print("=" * 60)
        for code in output["classification"]["icd_codes"]:
            print(f"  {code['code']}: {code['description']} "
                  f"(confidence: {code['confidence']:.1%})")

        print(f"\nRisk score: {output['classification']['risk_score']:.1%}")
        if output["classification"]["risk_factors"]:
            print("Risk factors:")
            for factor in output["classification"]["risk_factors"]:
                print(f"  - {factor}")

        if args.output:
            output_path = Path(args.output)
            output_path.write_text(json.dumps(output, indent=2))
            print(f"\nFull result saved to {output_path}")

    else:
        error_message = result.get("errorMessage") or result.get("error_message")
        if error_message:
            print(f"Error: {error_message}")
        print(f"Processing failed with status: {status}")
        sys.exit(1)


def cmd_status(args):
    """Check job status."""
    client = MedSealClient(args.gateway_url)
    status = client.get_status(args.job_id)
    print(json.dumps(status, indent=2, default=str))


def cmd_health(args):
    """Check gateway health."""
    client = MedSealClient(args.gateway_url)
    health = client.health()
    print(json.dumps(health, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="MedSeal CLI: Confidential medical data processing"
    )
    parser.add_argument(
        "--gateway-url", default=DEFAULT_GATEWAY_URL,
        help=f"Gateway URL (default: {DEFAULT_GATEWAY_URL})"
    )
    parser.add_argument(
        "--region", default=DEFAULT_REGION,
        help=f"AWS region (default: {DEFAULT_REGION})"
    )
    parser.add_argument(
        "--kms-key-id", default=DEFAULT_KMS_KEY_ID,
        help=f"KMS key ID (default: {DEFAULT_KMS_KEY_ID})"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    ep = subparsers.add_parser("encrypt-and-process", help="Encrypt and submit a file")
    ep.add_argument("--file", "-f", required=True, help="Path to medical record file")
    ep.add_argument("--output", "-o", help="Save decrypted result to file")
    ep.add_argument("--job-id", help="UUID to bind into the KMS encryption context")
    ep.add_argument("--debug-tamper-context", action="store_true", help=argparse.SUPPRESS)
    ep.add_argument(
        "--principal",
        default=DEFAULT_PRINCIPAL,
        help="Gateway-authenticated principal to bind into KMS/AAD context; must match the bearer identity",
    )
    ep.set_defaults(func=cmd_encrypt_and_process)

    st = subparsers.add_parser("status", help="Check job status")
    st.add_argument("--job-id", required=True, help="Job ID")
    st.set_defaults(func=cmd_status)

    hl = subparsers.add_parser("health", help="Check gateway health")
    hl.set_defaults(func=cmd_health)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
