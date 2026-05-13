"""Runtime configuration shared by enclave services."""

from __future__ import annotations

import os

IS_PRODUCTION = os.getenv("MEDSEAL_ENV", "development") == "production"
