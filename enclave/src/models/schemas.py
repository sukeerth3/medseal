"""Dataclasses used for vsock request and response payloads."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum


class JobStatus(str, Enum):
    RECEIVED = "RECEIVED"
    ATTESTING = "ATTESTING"
    DECRYPTING = "DECRYPTING"
    PROCESSING = "PROCESSING"
    ENCRYPTING = "ENCRYPTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class ProcessRequest:
    """Incoming encrypted payload from the gateway."""

    job_id: str
    principal: str
    encryption_context: dict[str, str]
    ciphertext_b64: str          # Base64-encoded AES-256-GCM ciphertext
    encrypted_data_key_b64: str  # Base64-encoded KMS-wrapped data key
    iv_b64: str                  # Base64-encoded initialization vector
    auth_tag_b64: str            # Base64-encoded GCM authentication tag
    kms_key_id: str              # KMS key ARN used for envelope encryption
    aws_access_key_id: str       # Temporary parent-instance credentials
    aws_secret_access_key: str
    aws_session_token: str
    type: str = "process"

    @classmethod
    def from_json(cls, raw: str) -> ProcessRequest:
        data = json.loads(raw)
        # Preserve compatibility with older process requests that omitted type.
        data.setdefault("type", "process")
        if data["type"] != "process":
            raise ValueError(f"Unexpected request type for ProcessRequest: {data['type']}")
        if "encryption_context" not in data:
            data["encryption_context"] = {
                "jobId": data.get("job_id", ""),
                "principal": data.get("principal", ""),
            }
        return cls(**data)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    def canonical_encryption_context(self) -> dict[str, str]:
        context = dict(self.encryption_context)
        expected = {"jobId": self.job_id, "principal": self.principal}
        if context != expected:
            raise ValueError("encryption context does not match request job_id/principal")
        return expected


@dataclass(frozen=True)
class DeidentificationResult:
    """Output of the PHI de-identification pipeline."""

    deidentified_text: str
    entities_found: list[dict]    # [{type, start, end, original, replacement}]
    entity_count: int
    confidence_score: float       # Average NER confidence

    @classmethod
    def from_dict(cls, data: dict) -> DeidentificationResult:
        return cls(**data)


@dataclass(frozen=True)
class ClassificationResult:
    """Output of the ICD-10 classification step."""

    icd_codes: list[dict]         # [{code, description, confidence}]
    risk_score: float             # 0.0 - 1.0 composite risk
    risk_factors: list[str]

    @classmethod
    def from_dict(cls, data: dict) -> ClassificationResult:
        return cls(**data)


@dataclass(frozen=True)
class ProcessingOutput:
    """Combined processing result before re-encryption."""

    job_id: str
    deidentification: DeidentificationResult
    classification: ClassificationResult
    processed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass(frozen=True)
class ProcessResponse:
    """Encrypted response sent back to the gateway via vsock."""

    job_id: str
    status: str
    encrypted_result_b64: str     # Base64-encoded encrypted ProcessingOutput
    encrypted_data_key_b64: str   # Base64-encoded KMS-wrapped result key
    iv_b64: str
    auth_tag_b64: str
    attestation_hash: str         # SHA-256 of the attestation doc used
    processing_time_ms: int
    encryption_context: dict[str, str] = field(default_factory=dict)
    error_message: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def error(cls, job_id: str, error_msg: str) -> ProcessResponse:
        return cls(
            job_id=job_id,
            status=JobStatus.FAILED.value,
            encrypted_result_b64="",
            encrypted_data_key_b64="",
            iv_b64="",
            auth_tag_b64="",
            attestation_hash="",
            processing_time_ms=0,
            encryption_context={},
            error_message=error_msg,
        )


@dataclass(frozen=True)
class HealthRequest:
    """Typed health probe request."""

    type: str = "health"

    @classmethod
    def from_json(cls, raw: str) -> HealthRequest:
        data = json.loads(raw)
        if data.get("type") != "health":
            raise ValueError("HealthRequest requires type='health'")
        return cls(type=data["type"])


@dataclass(frozen=True)
class HealthResponse:
    """Structured enclave health response."""

    status: str
    nsm_available: bool
    kms_reachable: bool
    spacy_loaded: bool
    type: str = "health"

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass(frozen=True)
class StatusUpdate:
    """Real-time status update sent to the gateway for WebSocket broadcast."""

    job_id: str
    status: str
    message: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_json(self) -> str:
        return json.dumps(asdict(self))
