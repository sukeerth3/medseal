"""Keyword-based ICD-10 condition classifier."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IcdMatch:
    """A matched ICD-10 code."""

    code: str
    description: str
    confidence: float     # Match confidence
    matched_terms: list[str]


# Curated rules for the prototype workload. A production classifier would
# use a maintained coding source or clinical NLP model.
ICD10_RULES: list[dict] = [
    {
        "code": "I10",
        "description": "Essential (primary) hypertension",
        "keywords": ["hypertension", "high blood pressure", "elevated bp", "htn"],
        "risk_weight": 0.6,
    },
    {
        "code": "E11",
        "description": "Type 2 diabetes mellitus",
        "keywords": ["type 2 diabetes", "diabetes mellitus", "t2dm", "type ii diabetes", "dm2"],
        "risk_weight": 0.7,
    },
    {
        "code": "E78.5",
        "description": "Hyperlipidemia, unspecified",
        "keywords": ["hyperlipidemia", "high cholesterol", "elevated cholesterol", "dyslipidemia"],
        "risk_weight": 0.4,
    },
    {
        "code": "J06.9",
        "description": "Acute upper respiratory infection, unspecified",
        "keywords": ["upper respiratory infection", "uri", "common cold", "nasopharyngitis"],
        "risk_weight": 0.1,
    },
    {
        "code": "M54.5",
        "description": "Low back pain",
        "keywords": ["low back pain", "lumbar pain", "lumbago", "back pain"],
        "risk_weight": 0.2,
    },
    {
        "code": "F32.9",
        "description": "Major depressive disorder, single episode, unspecified",
        "keywords": ["depression", "major depressive", "depressive disorder", "mdd"],
        "risk_weight": 0.5,
    },
    {
        "code": "F41.1",
        "description": "Generalized anxiety disorder",
        "keywords": ["anxiety", "generalized anxiety", "gad", "anxiety disorder"],
        "risk_weight": 0.4,
    },
    {
        "code": "J45",
        "description": "Asthma",
        "keywords": ["asthma", "reactive airway", "bronchial asthma", "asthmatic"],
        "risk_weight": 0.4,
    },
    {
        "code": "I25.10",
        "description": "Atherosclerotic heart disease",
        "keywords": ["coronary artery disease", "cad", "atherosclerotic", "ischemic heart", "coronary heart disease"],
        "risk_weight": 0.8,
    },
    {
        "code": "N18.9",
        "description": "Chronic kidney disease, unspecified",
        "keywords": ["chronic kidney disease", "ckd", "renal insufficiency", "kidney disease"],
        "risk_weight": 0.7,
    },
    {
        "code": "J44.1",
        "description": "Chronic obstructive pulmonary disease",
        "keywords": ["copd", "chronic obstructive pulmonary", "emphysema", "chronic bronchitis"],
        "risk_weight": 0.6,
    },
    {
        "code": "I48",
        "description": "Atrial fibrillation and flutter",
        "keywords": ["atrial fibrillation", "afib", "a-fib", "atrial flutter"],
        "risk_weight": 0.7,
    },
    {
        "code": "E03.9",
        "description": "Hypothyroidism, unspecified",
        "keywords": ["hypothyroidism", "underactive thyroid", "low thyroid"],
        "risk_weight": 0.3,
    },
    {
        "code": "K21.0",
        "description": "Gastro-esophageal reflux disease",
        "keywords": ["gerd", "acid reflux", "gastroesophageal reflux", "heartburn"],
        "risk_weight": 0.2,
    },
]


class MedicalClassifier:
    """
    ICD-10 classification engine.

    Matches medical text against a curated set of ICD-10 codes
    using keyword matching. Returns matched codes and a composite
    risk score.
    """

    def __init__(self, rules: list[dict] | None = None):
        self._rules = rules or ICD10_RULES
        self._compiled_rules = []
        for rule in self._rules:
            patterns = [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in rule["keywords"]]
            self._compiled_rules.append({
                **rule,
                "patterns": patterns,
            })
        logger.info("Initialized classifier with %d ICD-10 rules", len(self._rules))

    def classify(self, text: str) -> tuple[list[IcdMatch], float, list[str]]:
        """
        Classify medical text against ICD-10 codes.

        Returns: (matched codes, composite risk score, risk factors)
        """
        matches: list[IcdMatch] = []

        for rule in self._compiled_rules:
            matched_terms = []
            for pattern in rule["patterns"]:
                if pattern.search(text):
                    matched_terms.append(pattern.pattern.replace(r"\b", ""))

            if matched_terms:
                keyword_coverage = len(matched_terms) / len(rule["keywords"])
                confidence = min(0.95, 0.5 + keyword_coverage * 0.45)

                matches.append(
                    IcdMatch(
                        code=rule["code"],
                        description=rule["description"],
                        confidence=round(confidence, 3),
                        matched_terms=matched_terms,
                    )
                )

        risk_score = 0.0
        risk_factors: list[str] = []

        if matches:
            weights = []
            for match in matches:
                rule = next(r for r in self._rules if r["code"] == match.code)
                weight = rule["risk_weight"]
                weights.append(weight)
                if weight >= 0.6:
                    risk_factors.append(f"{match.description} ({match.code})")

            risk_score = min(1.0, sum(weights) / max(len(weights), 1) + 0.05 * len(weights))
            risk_score = round(risk_score, 3)

        logger.info(
            "Classified %d ICD-10 codes, risk score: %.3f",
            len(matches),
            risk_score,
        )

        return matches, risk_score, risk_factors
