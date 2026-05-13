#!/bin/bash
# Extract PCR measurements from the built EIF and emit Terraform tfvars.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EIF_PATH="${1:-$(dirname "$SCRIPT_DIR")/build/medseal.eif}"

if [ ! -f "$EIF_PATH" ]; then
    echo "ERROR: EIF not found at $EIF_PATH" >&2
    echo "Run ./scripts/build-enclave.sh first" >&2
    exit 1
fi

echo "Extracting PCR values from $EIF_PATH" >&2
DESCRIBE_OUTPUT="$(nitro-cli describe-eif --eif-path "$EIF_PATH")"
echo "$DESCRIBE_OUTPUT" >&2

printf '%s\n' "$DESCRIBE_OUTPUT" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
pcrs = data.get("Measurements", {})
mapping = {
    "allowed_pcr0": pcrs.get("PCR0"),
    "allowed_pcr1": pcrs.get("PCR1"),
    "allowed_pcr2": pcrs.get("PCR2"),
}
missing = [name for name, value in mapping.items() if not value]
if missing:
    print(f"ERROR: missing PCR values: {missing}", file=sys.stderr)
    sys.exit(1)
for name, value in mapping.items():
    print(f"{name} = \"{value}\"")
'
