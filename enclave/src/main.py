"""
MedSeal enclave entrypoint.

This module wires the enclave services and starts the vsock listener.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
import time

from . import config
from .attestation.service import AttestationService, NitroAttestationProvider
from .crypto.service import AwsCredentials, CryptoService, NitroKmsClient, MockKmsClient
from .processing.pipeline import ProcessingPipeline
from .processing.deidentifier import Deidentifier, SpacyDetector, RegexDetector
from .processing.classifier import MedicalClassifier
from .transport.vsock import VsockServer
from .models.schemas import (
    HealthRequest,
    HealthResponse,
    ProcessRequest,
    ProcessResponse,
    JobStatus,
)

# Never log PHI or decrypted record text.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("medseal.enclave")


class EnclaveApplication:
    """
    Wires enclave dependencies and handles encrypted request messages.
    """

    def __init__(self):
        region = os.environ.get("AWS_REGION", "us-east-1")
        kms_key_id = os.environ.get("KMS_KEY_ID", "alias/medseal-master")
        vsock_port = int(os.environ.get("VSOCK_PORT", "5000"))

        logger.info(
            "Initializing MedSeal enclave (production=%s, region=%s)",
            config.IS_PRODUCTION,
            region,
        )

        self._attestation = AttestationService()

        if config.IS_PRODUCTION:
            kms_client = NitroKmsClient(region=region)
        else:
            kms_client = MockKmsClient()

        self._crypto = CryptoService(kms_client=kms_client)
        self._kms_key_id = kms_key_id

        # Production images include the spaCy model; local runs may use regex only.
        try:
            detectors = [SpacyDetector(), RegexDetector()]
        except Exception as e:
            if config.IS_PRODUCTION:
                raise
            logger.warning("spaCy not available, using regex-only: %s", e)
            detectors = [RegexDetector()]
        self._spacy_loaded = any(detector.name() == "spacy_ner" for detector in detectors)

        self._pipeline = ProcessingPipeline(
            deidentifier=Deidentifier(detectors=detectors),
            classifier=MedicalClassifier(),
        )

        self._server = VsockServer(port=vsock_port)
        self._server.set_handler(self._handle_request)

        self._run_startup_self_test()

        logger.info("Enclave initialization complete")

    def run(self) -> None:
        """Start the enclave vsock server (blocking)."""
        logger.info("Starting vsock server...")
        try:
            self._server.start()
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
        finally:
            self._server.stop()

    def _handle_request(self, raw_message: str) -> str:
        """
        Handle a single processing request.

        Logs include job state only; request bodies are never logged.
        """
        start_time = time.monotonic()
        request: ProcessRequest | None = None
        job_id = "unknown"

        try:
            envelope = json.loads(raw_message)
            request_type = envelope.get("type", "process")
            if request_type == "health":
                return self._handle_health_request(raw_message)
            if request_type != "process":
                raise ValueError(f"Unsupported request type: {request_type}")

            request = ProcessRequest.from_json(json.dumps(envelope))
            job_id = request.job_id
            encryption_context = request.canonical_encryption_context()
            logger.info("[%s] Processing request received", job_id)

            kms_credentials = AwsCredentials(
                access_key_id=request.aws_access_key_id,
                secret_access_key=request.aws_secret_access_key,
                session_token=request.aws_session_token,
            )

            # This document is used for the audit hash. kmstool performs its
            # own NSM attestation for the KMS key-release call.
            logger.info("[%s] Generating attestation document", job_id)
            attestation = self._attestation.attest(
                user_data=base64.b64decode(request.encrypted_data_key_b64),
            )

            logger.info("[%s] Decrypting payload via KMS", job_id)
            plaintext_bytes = self._crypto.decrypt_payload(
                ciphertext=base64.b64decode(request.ciphertext_b64),
                encrypted_data_key=base64.b64decode(request.encrypted_data_key_b64),
                iv=base64.b64decode(request.iv_b64),
                auth_tag=base64.b64decode(request.auth_tag_b64),
                kms_key_id=request.kms_key_id,
                encryption_context=encryption_context,
                credentials=kms_credentials,
            )
            plaintext = plaintext_bytes.decode("utf-8")

            # Plaintext exists only inside enclave memory from here until cleanup.
            logger.info("[%s] Running processing pipeline", job_id)
            output = self._pipeline.process(job_id=job_id, plaintext=plaintext)

            logger.info("[%s] Encrypting results", job_id)
            result_json = output.to_json().encode("utf-8")
            (
                result_ciphertext,
                result_encrypted_key,
                result_iv,
                result_auth_tag,
            ) = self._crypto.encrypt_result(
                plaintext=result_json,
                kms_key_id=self._kms_key_id,
                encryption_context=encryption_context,
                credentials=kms_credentials,
            )

            # Best-effort cleanup for Python objects holding plaintext.
            del plaintext
            del plaintext_bytes
            del result_json
            del kms_credentials

            elapsed_ms = int((time.monotonic() - start_time) * 1000)

            response = ProcessResponse(
                job_id=job_id,
                status=JobStatus.COMPLETED.value,
                encrypted_result_b64=base64.b64encode(result_ciphertext).decode(),
                encrypted_data_key_b64=base64.b64encode(result_encrypted_key).decode(),
                iv_b64=base64.b64encode(result_iv).decode(),
                auth_tag_b64=base64.b64encode(result_auth_tag).decode(),
                attestation_hash=attestation.hash,
                processing_time_ms=elapsed_ms,
                encryption_context=encryption_context,
            )

            logger.info(
                "[%s] Request completed in %dms", job_id, elapsed_ms
            )
            return response.to_json()

        except Exception as e:
            logger.error("[%s] Processing failed: %s", job_id, e)
            error_response = ProcessResponse.error(
                job_id=request.job_id if request is not None else "unknown",
                error_msg=str(e),
            )
            return error_response.to_json()

    def _handle_health_request(self, raw_message: str) -> str:
        HealthRequest.from_json(raw_message)
        nsm_available = NitroAttestationProvider().is_available()
        spacy_loaded = self._spacy_loaded
        try:
            kms_reachable = self._crypto.check_kms_connectivity(self._kms_key_id)
        except Exception as exc:
            logger.warning("KMS health check failed: %s", exc)
            kms_reachable = False

        status = "OK"
        if config.IS_PRODUCTION and not (nsm_available and kms_reachable and spacy_loaded):
            status = "FAILED"

        return HealthResponse(
            status=status,
            nsm_available=nsm_available,
            kms_reachable=kms_reachable,
            spacy_loaded=spacy_loaded,
        ).to_json()

    def _run_startup_self_test(self) -> None:
        try:
            if config.IS_PRODUCTION and not self._attestation.is_available():
                raise RuntimeError("NSM device is not available")
            if not self._crypto.check_kms_connectivity(self._kms_key_id):
                raise RuntimeError("kmstool-enclave-cli is not invocable")
        except Exception as exc:
            if config.IS_PRODUCTION:
                raise RuntimeError("MEDSEAL: startup self-test failed") from exc
            logger.warning("Startup self-test skipped/failed outside production: %s", exc)


def main():
    """Entrypoint for the enclave application."""
    logger.info("=" * 60)
    logger.info("MedSeal Enclave Starting")
    logger.info("=" * 60)

    app = EnclaveApplication()
    app.run()


if __name__ == "__main__":
    main()
