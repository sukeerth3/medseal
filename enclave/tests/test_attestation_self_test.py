import importlib

import pytest


def test_app_startup_raises_with_mock_nsm_in_production(monkeypatch):
    import src.config as config
    from src.attestation import service as attestation_service

    monkeypatch.setenv("MEDSEAL_ENV", "production")
    importlib.reload(config)
    monkeypatch.setattr(
        attestation_service.NitroAttestationProvider,
        "NSM_DEVICE",
        "/tmp/medseal-test-missing-nsm",
    )

    from src.main import EnclaveApplication

    with pytest.raises(RuntimeError, match="production requires real NSM"):
        EnclaveApplication()
