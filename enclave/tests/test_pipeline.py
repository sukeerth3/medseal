"""
Unit tests for the MedSeal enclave processing pipeline.

These tests run outside the enclave (no NSM device needed)
using mock providers. They validate the processing logic
independently from the transport and attestation layers.
"""

import json
import pytest
from unittest.mock import MagicMock

# Test de-identifier
from src.processing.deidentifier import (
    Deidentifier,
    RegexDetector,
    PhiEntity,
)
from src.processing.classifier import MedicalClassifier
from src.processing.pipeline import ProcessingPipeline
from src.models.schemas import ProcessRequest, ProcessResponse, JobStatus


class TestRegexDetector:
    """Test the regex-based PHI detector."""

    def setup_method(self):
        self.detector = RegexDetector()

    def test_detects_ssn(self):
        text = "Patient SSN is 123-45-6789."
        entities = self.detector.detect(text)
        ssn_entities = [e for e in entities if e.entity_type == "SSN"]
        assert len(ssn_entities) == 1
        assert ssn_entities[0].original == "123-45-6789"

    def test_detects_phone(self):
        text = "Contact: (515) 620-1718"
        entities = self.detector.detect(text)
        phone_entities = [e for e in entities if e.entity_type == "PHONE"]
        assert len(phone_entities) == 1

    def test_detects_email(self):
        text = "Email: patient@hospital.com"
        entities = self.detector.detect(text)
        email_entities = [e for e in entities if e.entity_type == "EMAIL"]
        assert len(email_entities) == 1
        assert email_entities[0].original == "patient@hospital.com"

    def test_detects_date(self):
        text = "DOB: 03/15/1990"
        entities = self.detector.detect(text)
        date_entities = [e for e in entities if e.entity_type == "DATE_NUMERIC"]
        assert len(date_entities) == 1

    def test_detects_mrn(self):
        text = "MRN: 12345678"
        entities = self.detector.detect(text)
        mrn_entities = [e for e in entities if e.entity_type == "MRN"]
        assert len(mrn_entities) == 1

    def test_no_false_positives_on_clean_text(self):
        text = "The patient presents with mild symptoms."
        entities = self.detector.detect(text)
        assert len(entities) == 0


class TestDeidentifier:
    """Test the multi-layer de-identification engine."""

    def setup_method(self):
        # Use only regex detector for unit tests (no spaCy dependency)
        self.deid = Deidentifier(detectors=[RegexDetector()])

    def test_redacts_ssn(self):
        text = "Patient John, SSN 123-45-6789, presented today."
        result, entities = self.deid.deidentify(text)
        assert "123-45-6789" not in result
        assert "[REDACTED_SSN]" in result

    def test_redacts_multiple_phi(self):
        text = "SSN: 123-45-6789, Phone: (515) 620-1718, Email: test@test.com"
        result, entities = self.deid.deidentify(text)
        assert "123-45-6789" not in result
        assert "620-1718" not in result
        assert "test@test.com" not in result
        assert len(entities) == 3

    def test_preserves_non_phi_text(self):
        text = "Patient has hypertension and diabetes."
        result, entities = self.deid.deidentify(text)
        assert result == text
        assert len(entities) == 0

    def test_handles_empty_text(self):
        result, entities = self.deid.deidentify("")
        assert result == ""
        assert len(entities) == 0

    def test_merge_overlapping_entities(self):
        # Create overlapping entities
        entities = [
            PhiEntity("SSN", 10, 21, "123-45-6789", "[SSN]", 0.95, "regex"),
            PhiEntity("PHONE", 10, 24, "123-45-6789-00", "[PHONE]", 0.80, "regex"),
        ]
        merged = Deidentifier._merge_overlapping(entities)
        assert len(merged) == 1
        assert merged[0].confidence == 0.95  # Higher confidence wins


class TestMedicalClassifier:
    """Test ICD-10 classification."""

    def setup_method(self):
        self.classifier = MedicalClassifier()

    def test_classifies_hypertension(self):
        text = "Patient diagnosed with hypertension. BP 160/95."
        matches, risk, factors = self.classifier.classify(text)
        codes = [m.code for m in matches]
        assert "I10" in codes

    def test_classifies_diabetes(self):
        text = "History of type 2 diabetes mellitus, on metformin."
        matches, risk, factors = self.classifier.classify(text)
        codes = [m.code for m in matches]
        assert "E11" in codes

    def test_classifies_multiple_conditions(self):
        text = "Patient with hypertension, type 2 diabetes, and chronic kidney disease."
        matches, risk, factors = self.classifier.classify(text)
        codes = [m.code for m in matches]
        assert "I10" in codes
        assert "E11" in codes
        assert "N18.9" in codes
        assert risk > 0.5  # Multiple serious conditions = higher risk

    def test_no_matches_on_unrelated_text(self):
        text = "The weather today is sunny and warm."
        matches, risk, factors = self.classifier.classify(text)
        assert len(matches) == 0
        assert risk == 0.0

    def test_risk_score_range(self):
        text = "Coronary artery disease with atrial fibrillation and chronic kidney disease."
        matches, risk, factors = self.classifier.classify(text)
        assert 0.0 <= risk <= 1.0
        assert len(factors) > 0  # Should have high-risk factors


class TestProcessingPipeline:
    """Test the end-to-end processing pipeline."""

    def setup_method(self):
        self.pipeline = ProcessingPipeline(
            deidentifier=Deidentifier(detectors=[RegexDetector()]),
            classifier=MedicalClassifier(),
        )

    def test_full_pipeline(self):
        text = (
            "Patient SSN 123-45-6789 presents with hypertension "
            "and type 2 diabetes. Phone: (515) 620-1718."
        )
        output = self.pipeline.process(job_id="test-001", plaintext=text)

        # Check de-identification
        assert output.deidentification.entity_count >= 2
        assert "123-45-6789" not in output.deidentification.deidentified_text

        # Check classification
        codes = [c["code"] for c in output.classification.icd_codes]
        assert "I10" in codes or "E11" in codes

        # Check structure
        assert output.job_id == "test-001"
        assert output.processed_at is not None

    def test_pipeline_serialization(self):
        text = "Patient with hypertension."
        output = self.pipeline.process(job_id="test-002", plaintext=text)
        json_str = output.to_json()
        parsed = json.loads(json_str)
        assert parsed["job_id"] == "test-002"
        assert "deidentification" in parsed
        assert "classification" in parsed


class TestSchemas:
    """Test data model serialization."""

    def test_process_request_roundtrip(self):
        request = ProcessRequest(
            job_id="test-001",
            principal="principal-a",
            encryption_context={"jobId": "test-001", "principal": "principal-a"},
            ciphertext_b64="Y2lwaGVydGV4dA==",
            encrypted_data_key_b64="ZW5jcnlwdGVk",
            iv_b64="aXY=",
            auth_tag_b64="dGFn",
            kms_key_id="alias/test",
            aws_access_key_id="AKIA_TEST",
            aws_secret_access_key="secret",
            aws_session_token="token",
        )
        json_str = request.to_json()
        restored = ProcessRequest.from_json(json_str)
        assert restored.job_id == request.job_id
        assert restored.kms_key_id == request.kms_key_id
        assert restored.canonical_encryption_context() == request.encryption_context

    def test_error_response(self):
        response = ProcessResponse.error("test-001", "something broke")
        assert response.status == JobStatus.FAILED.value
        assert response.job_id == "test-001"
        assert response.error_message == "something broke"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
