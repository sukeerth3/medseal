"""Medical record processing pipeline."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from ..models.schemas import (
    DeidentificationResult,
    ClassificationResult,
    ProcessingOutput,
)
from .deidentifier import Deidentifier
from .classifier import MedicalClassifier

logger = logging.getLogger(__name__)


class ProcessingPipeline:
    """
    End-to-end medical record processing pipeline.

    Runs inside the enclave on decrypted plaintext. The pipeline
    is stateless and can process records independently.
    """

    def __init__(
        self,
        deidentifier: Deidentifier | None = None,
        classifier: MedicalClassifier | None = None,
    ):
        self._deidentifier = deidentifier or Deidentifier()
        self._classifier = classifier or MedicalClassifier()
        logger.info("Processing pipeline initialized")

    def process(self, job_id: str, plaintext: str) -> ProcessingOutput:
        """
        Process a decrypted medical record.

        Args:
            job_id: Unique job identifier for tracking
            plaintext: Decrypted medical record text

        Returns:
            ProcessingOutput with de-identified text, ICD codes, and risk score
        """
        start_time = time.monotonic()

        logger.info("[%s] Stage 1: De-identifying PHI", job_id)
        deidentified_text, entities = self._deidentifier.deidentify(plaintext)

        deidentification = DeidentificationResult(
            deidentified_text=deidentified_text,
            entities_found=[
                {
                    "type": e.entity_type,
                    "start": e.start,
                    "end": e.end,
                    "original_length": len(e.original),
                    "replacement": e.replacement,
                    "confidence": e.confidence,
                    "source": e.source,
                }
                for e in entities
            ],
            entity_count=len(entities),
            confidence_score=round(
                sum(e.confidence for e in entities) / max(len(entities), 1),
                3,
            ),
        )

        logger.info("[%s] Stage 2: Classifying medical conditions", job_id)
        icd_matches, risk_score, risk_factors = self._classifier.classify(
            deidentified_text
        )

        classification = ClassificationResult(
            icd_codes=[
                {
                    "code": m.code,
                    "description": m.description,
                    "confidence": m.confidence,
                    "matched_terms": m.matched_terms,
                }
                for m in icd_matches
            ],
            risk_score=risk_score,
            risk_factors=risk_factors,
        )

        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        logger.info(
            "[%s] Pipeline complete: %d PHI entities, %d ICD codes, "
            "risk=%.3f, %dms",
            job_id,
            deidentification.entity_count,
            len(classification.icd_codes),
            classification.risk_score,
            elapsed_ms,
        )

        return ProcessingOutput(
            job_id=job_id,
            deidentification=deidentification,
            classification=classification,
        )
