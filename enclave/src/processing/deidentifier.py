"""PHI detection and redaction."""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from .. import config

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PhiEntity:
    """A detected PHI entity in the text."""

    entity_type: str      # PERSON, DATE, SSN, MRN, PHONE, EMAIL, etc.
    start: int            # Character offset start
    end: int              # Character offset end
    original: str         # Original text
    replacement: str      # Replacement token
    confidence: float     # Detection confidence (0.0 - 1.0)
    source: str           # Which detector found it (spacy, regex, etc.)


class PhiDetector(ABC):
    """Interface for PHI detectors."""

    @abstractmethod
    def detect(self, text: str) -> list[PhiEntity]:
        """Detect PHI entities in the given text."""
        ...

    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this detector."""
        ...


class SpacyDetector(PhiDetector):
    """
    spaCy NER-based PHI detector.

    Uses the en_core_web_sm model for entity recognition.
    Detects: PERSON, DATE, ORG, GPE (geo-political entities).
    """

    LABEL_MAP = {
        "PERSON": "PERSON",
        "DATE": "DATE",
        "ORG": "ORGANIZATION",
        "GPE": "LOCATION",
        "LOC": "LOCATION",
        "FAC": "FACILITY",
    }

    REPLACEMENTS = {
        "PERSON": "[REDACTED_NAME]",
        "DATE": "[REDACTED_DATE]",
        "ORGANIZATION": "[REDACTED_ORG]",
        "LOCATION": "[REDACTED_LOCATION]",
        "FACILITY": "[REDACTED_FACILITY]",
    }

    def __init__(self, model_name: str = "en_core_web_sm"):
        try:
            import spacy
            self._nlp = spacy.load(model_name)
            logger.info("Loaded spaCy model: %s", model_name)
        except OSError:
            logger.error(
                "spaCy model '%s' not found. "
                "Run: python -m spacy download %s",
                model_name,
                model_name,
            )
            if config.IS_PRODUCTION:
                raise RuntimeError("MEDSEAL: production requires spaCy PHI model")
            raise

    def name(self) -> str:
        return "spacy_ner"

    def detect(self, text: str) -> list[PhiEntity]:
        doc = self._nlp(text)
        entities = []

        for ent in doc.ents:
            phi_type = self.LABEL_MAP.get(ent.label_)
            if phi_type is None:
                continue

            replacement = self.REPLACEMENTS.get(phi_type, f"[REDACTED_{phi_type}]")

            entities.append(
                PhiEntity(
                    entity_type=phi_type,
                    start=ent.start_char,
                    end=ent.end_char,
                    original=ent.text,
                    replacement=replacement,
                    confidence=round(max(0.5, ent._.get("score", 0.75)) if hasattr(ent._, "score") else 0.75, 3),
                    source=self.name(),
                )
            )

        return entities


class RegexDetector(PhiDetector):
    """
    Regex-based PHI detector for structured identifiers.

    Catches PHI that NER models typically miss: SSNs, MRNs,
    phone numbers, email addresses, ZIP codes.
    """

    PATTERNS = [
        {
            "type": "SSN",
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "replacement": "[REDACTED_SSN]",
        },
        {
            "type": "MRN",
            "pattern": r"\b(?:MRN|Medical Record Number|Record #?)[\s:]*(\d{6,10})\b",
            "replacement": "[REDACTED_MRN]",
        },
        {
            "type": "PHONE",
            "pattern": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "replacement": "[REDACTED_PHONE]",
        },
        {
            "type": "EMAIL",
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "replacement": "[REDACTED_EMAIL]",
        },
        {
            "type": "DATE_NUMERIC",
            "pattern": r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
            "replacement": "[REDACTED_DATE]",
        },
        {
            "type": "ZIP_CODE",
            "pattern": r"\b\d{5}(?:-\d{4})?\b",
            "replacement": "[REDACTED_ZIP]",
        },
    ]

    def name(self) -> str:
        return "regex"

    def detect(self, text: str) -> list[PhiEntity]:
        entities = []

        for pattern_def in self.PATTERNS:
            for match in re.finditer(pattern_def["pattern"], text, re.IGNORECASE):
                entities.append(
                    PhiEntity(
                        entity_type=pattern_def["type"],
                        start=match.start(),
                        end=match.end(),
                        original=match.group(),
                        replacement=pattern_def["replacement"],
                        confidence=0.95,  # Regex matches are high confidence
                        source=self.name(),
                    )
                )

        return entities


class Deidentifier:
    """
    Multi-layer PHI de-identification engine.

    Runs multiple detectors in sequence, merges overlapping
    entities (preferring higher-confidence matches), and
    applies replacements. Thread-safe and stateless.
    """

    def __init__(self, detectors: Optional[list[PhiDetector]] = None):
        if detectors is not None:
            self._detectors = detectors
        else:
            self._detectors = [
                SpacyDetector(),
                RegexDetector(),
            ]
        logger.info(
            "Initialized de-identifier with %d detectors: %s",
            len(self._detectors),
            [d.name() for d in self._detectors],
        )

    def deidentify(self, text: str) -> tuple[str, list[PhiEntity]]:
        """
        De-identify the given text.

        Returns: (de-identified text, list of detected entities)
        """
        all_entities = []
        for detector in self._detectors:
            try:
                entities = detector.detect(text)
                all_entities.extend(entities)
                logger.debug(
                    "%s found %d entities", detector.name(), len(entities)
                )
            except Exception as e:
                logger.error("Detector %s failed: %s", detector.name(), e)
                if config.IS_PRODUCTION:
                    raise RuntimeError(
                        f"MEDSEAL: PHI detector failed closed: {detector.name()}"
                    ) from e
                # Keep local development usable when one detector fails.

        if not all_entities:
            logger.info("No PHI entities detected")
            return text, []

        merged = self._merge_overlapping(all_entities)

        # Replace from right to left so earlier offsets stay valid.
        result = text
        for entity in sorted(merged, key=lambda e: e.start, reverse=True):
            result = result[: entity.start] + entity.replacement + result[entity.end:]

        logger.info("De-identified %d PHI entities", len(merged))
        return result, merged

    @staticmethod
    def _merge_overlapping(entities: list[PhiEntity]) -> list[PhiEntity]:
        """
        Merge overlapping entity spans, keeping the highest-confidence
        detection for each overlapping region.
        """
        if not entities:
            return []

        sorted_entities = sorted(
            entities, key=lambda e: (e.start, -e.confidence)
        )

        merged: list[PhiEntity] = [sorted_entities[0]]

        for current in sorted_entities[1:]:
            last = merged[-1]

            if current.start < last.end:
                if current.confidence > last.confidence:
                    merged[-1] = current
            else:
                merged.append(current)

        return merged
