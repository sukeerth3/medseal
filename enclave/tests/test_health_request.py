import importlib
import json


def test_health_request_returns_structured_health_response(monkeypatch):
    import src.config as config

    monkeypatch.setenv("MEDSEAL_ENV", "development")
    importlib.reload(config)

    from src.main import EnclaveApplication

    app = EnclaveApplication()
    response = json.loads(app._handle_request(json.dumps({"type": "health"})))

    assert response["type"] == "health"
    assert response["status"] == "OK"
    assert set(response) == {
        "type",
        "status",
        "nsm_available",
        "kms_reachable",
        "spacy_loaded",
    }
    assert isinstance(response["nsm_available"], bool)
    assert isinstance(response["kms_reachable"], bool)
    assert isinstance(response["spacy_loaded"], bool)
