"""Nitro Enclave attestation providers."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from .. import config

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AttestationDocument:
    """Wrapper around the raw attestation document bytes."""

    raw_document: bytes
    pcr0: str   # Enclave image hash
    pcr1: str   # Kernel hash
    pcr2: str   # Application hash
    digest: str  # SHA-256 of the raw document

    @property
    def hash(self) -> str:
        return self.digest


class AttestationProvider(ABC):
    """Interface for attestation document generation."""

    @abstractmethod
    def generate(
        self,
        public_key: Optional[bytes] = None,
        user_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> AttestationDocument:
        """Generate an attestation document."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the attestation hardware is available."""
        ...


class NitroAttestationProvider(AttestationProvider):
    """
    Production attestation provider using the Nitro Secure Module.

    Communicates with /dev/nsm to generate attestation documents
    signed by the Nitro Hypervisor. Only works inside an actual
    Nitro Enclave.
    """

    NSM_DEVICE = "/dev/nsm"

    def is_available(self) -> bool:
        return os.path.exists(self.NSM_DEVICE)

    def generate(
        self,
        public_key: Optional[bytes] = None,
        user_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> AttestationDocument:
        if not self.is_available():
            raise RuntimeError("NSM device not available. Are you inside a Nitro Enclave?")

        try:
            from .nsm_binding import (
                NsmError,
                NsmClient,
                extract_pcrs_from_attestation_document,
            )
        except ImportError as exc:
            msg = "MEDSEAL: production requires real NSM binding"
            if config.IS_PRODUCTION:
                raise RuntimeError(msg) from exc
            raise RuntimeError(f"{msg}: {exc}") from exc

        try:
            attestation_doc = NsmClient(device_path=self.NSM_DEVICE).get_attestation_doc(
                public_key=public_key,
                user_data=user_data,
                nonce=nonce,
            )
            digest = hashlib.sha256(attestation_doc).hexdigest()
            try:
                pcrs = extract_pcrs_from_attestation_document(attestation_doc)
            except NsmError as exc:
                # The audit hash only needs the raw NSM document. KMS release is
                # performed separately by kmstool-enclave-cli, which supplies its
                # own attestation document to KMS.
                logger.warning("Generated NSM attestation but could not parse PCRs: %s", exc)
                pcrs = {}

            logger.info(
                "Generated attestation document",
                extra={"digest": digest, "pcr0": pcrs.get(0, "")[:16] + "..."},
            )

            return AttestationDocument(
                raw_document=attestation_doc,
                pcr0=pcrs.get(0, ""),
                pcr1=pcrs.get(1, ""),
                pcr2=pcrs.get(2, ""),
                digest=digest,
            )
        except Exception as exc:
            msg = "MEDSEAL: real NSM attestation failed"
            if config.IS_PRODUCTION:
                raise RuntimeError(msg) from exc
            raise RuntimeError(f"{msg}: {exc}") from exc


class MockAttestationProvider(AttestationProvider):
    """
    Development/testing attestation provider.

    Generates deterministic mock attestation documents for local
    testing outside of a Nitro Enclave. Production startup rejects
    this provider.
    """

    MOCK_PCR0 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    MOCK_PCR1 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
    MOCK_PCR2 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"

    def is_available(self) -> bool:
        return True

    def generate(
        self,
        public_key: Optional[bytes] = None,
        user_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> AttestationDocument:
        mock_doc = json.dumps({
            "module_id": "medseal-mock",
            "public_key": public_key.hex() if public_key else None,
            "user_data": user_data.hex() if user_data else None,
            "nonce": nonce.hex() if nonce else None,
            "pcrs": {
                "0": self.MOCK_PCR0,
                "1": self.MOCK_PCR1,
                "2": self.MOCK_PCR2,
            },
        }).encode()

        digest = hashlib.sha256(mock_doc).hexdigest()

        logger.warning("Using mock attestation provider for local development")

        return AttestationDocument(
            raw_document=mock_doc,
            pcr0=self.MOCK_PCR0,
            pcr1=self.MOCK_PCR1,
            pcr2=self.MOCK_PCR2,
            digest=digest,
        )


class AttestationService:
    """
    Facade for attestation operations.

    Automatically selects the appropriate provider based on
    the runtime environment.
    """

    def __init__(self, provider: Optional[AttestationProvider] = None):
        if provider is not None:
            if config.IS_PRODUCTION and isinstance(provider, MockAttestationProvider):
                raise RuntimeError("MEDSEAL: production requires real NSM")
            if config.IS_PRODUCTION and not provider.is_available():
                raise RuntimeError("MEDSEAL: production requires real NSM")
            self._provider = provider
        else:
            nitro = NitroAttestationProvider()
            if nitro.is_available():
                self._provider = nitro
                logger.info("Using Nitro attestation provider (production)")
            else:
                if config.IS_PRODUCTION:
                    raise RuntimeError("MEDSEAL: production requires real NSM")
                self._provider = MockAttestationProvider()
                logger.warning("NSM device not found, falling back to mock provider")

    @property
    def provider_name(self) -> str:
        return type(self._provider).__name__

    def is_available(self) -> bool:
        return self._provider.is_available()

    def attest(
        self,
        public_key: Optional[bytes] = None,
        user_data: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> AttestationDocument:
        return self._provider.generate(
            public_key=public_key,
            user_data=user_data,
            nonce=nonce,
        )
