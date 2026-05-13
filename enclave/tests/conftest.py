import importlib
from pathlib import Path
import sys

import pytest

ENCLAVE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENCLAVE_DIR))


@pytest.fixture(autouse=True)
def reset_medseal_env(monkeypatch):
    import src.config as config

    monkeypatch.setenv("MEDSEAL_ENV", "development")
    importlib.reload(config)
    yield
    monkeypatch.setenv("MEDSEAL_ENV", "development")
    importlib.reload(config)
