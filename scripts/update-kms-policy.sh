#!/bin/bash
# Update the KMS policy through Terraform so live policy and state do not drift.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
INFRA_DIR="$PROJECT_DIR/infrastructure"
TFVARS_FILE="${1:-$INFRA_DIR/pcrs.auto.tfvars}"

[ -f "$TFVARS_FILE" ] || {
    echo "ERROR: PCR tfvars file not found: $TFVARS_FILE" >&2
    echo "Generate it with: ./scripts/extract-pcrs.sh build/medseal.eif > infrastructure/pcrs.auto.tfvars" >&2
    exit 1
}

if [[ "$TFVARS_FILE" != /* ]]; then
    TFVARS_FILE="$(cd "$(dirname "$TFVARS_FILE")" && pwd)/$(basename "$TFVARS_FILE")"
fi

echo "Applying Terraform-managed KMS PCR policy using $TFVARS_FILE"
terraform -chdir="$INFRA_DIR" apply -input=false -var-file="$TFVARS_FILE"
