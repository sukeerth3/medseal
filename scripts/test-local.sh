#!/bin/bash
# Run local checks that do not require live Nitro Enclave hardware.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PYTEST="${PYTEST:-$PROJECT_DIR/.venv/bin/pytest}"

cd "$PROJECT_DIR"

if [ ! -x "$PYTEST" ]; then
    echo "ERROR: pytest not found at $PYTEST" >&2
    echo "Run the README dependency setup first, or set PYTEST=/path/to/pytest." >&2
    exit 1
fi

echo "[1/5] Gateway unit tests"
mvn -f gateway/pom.xml -B test

echo "[2/5] Python unit tests"
PYTHONPATH=enclave "$PYTEST" enclave/tests cli/tests infrastructure/tests

echo "[3/5] React client build"
npm --prefix client run build

echo "[4/5] Terraform format check"
terraform -chdir=infrastructure fmt -check -recursive

echo "[5/5] Terraform provider init and validation"
terraform -chdir=infrastructure init -backend=false
terraform -chdir=infrastructure validate

echo "Local validation passed."
