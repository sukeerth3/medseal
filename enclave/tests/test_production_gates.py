import importlib

import pytest


def _set_production(monkeypatch):
    import src.config as config

    monkeypatch.setenv("MEDSEAL_ENV", "production")
    importlib.reload(config)
    return config


def test_attestation_service_requires_nsm_in_production(monkeypatch):
    _set_production(monkeypatch)

    from src.attestation import service as attestation_service

    monkeypatch.setattr(
        attestation_service.NitroAttestationProvider,
        "NSM_DEVICE",
        "/tmp/medseal-test-missing-nsm",
    )

    with pytest.raises(RuntimeError, match="production requires real NSM"):
        attestation_service.AttestationService()


def test_crypto_service_refuses_mock_kms_in_production(monkeypatch):
    _set_production(monkeypatch)

    from src.crypto.service import CryptoService, MockKmsClient

    with pytest.raises(RuntimeError, match="refuses MockKmsClient"):
        CryptoService(kms_client=MockKmsClient())
