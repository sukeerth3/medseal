#!/bin/bash
# Build the MedSeal Nitro Enclave image (EIF).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENCLAVE_DIR="$PROJECT_DIR/enclave"
OUTPUT_DIR="$PROJECT_DIR/build"
DOCKERFILE="$ENCLAVE_DIR/Dockerfile"
REQUIREMENTS="$ENCLAVE_DIR/requirements.txt"
KMSTOOL_CLI="$ENCLAVE_DIR/bin/kmstool_enclave_cli"
KMSTOOL_LIBNSM="$ENCLAVE_DIR/bin/libnsm.so"
PYTHON_VERSION="${PYTHON_VERSION:-3.11.14}"
PINNED_BASE_IMAGE="python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d"

echo "=== MedSeal Enclave Build ==="

mkdir -p "$OUTPUT_DIR"

if ! grep -Fxq "FROM $PINNED_BASE_IMAGE" "$DOCKERFILE"; then
    echo "ERROR: $DOCKERFILE must pin the base image to: $PINNED_BASE_IMAGE" >&2
    exit 1
fi

if [ ! -x "$KMSTOOL_CLI" ] || [ ! -f "$KMSTOOL_LIBNSM" ]; then
    echo "Building kmstool-enclave-cli artifacts..."
    "$SCRIPT_DIR/build-kmstool.sh"
fi

DOCKERFILE_SHA="$(sha256sum "$DOCKERFILE" | awk '{print $1}')"
REQUIREMENTS_SHA="$(sha256sum "$REQUIREMENTS" | awk '{print $1}')"
KMSTOOL_CLI_SHA="$(sha256sum "$KMSTOOL_CLI" | awk '{print $1}')"
KMSTOOL_LIBNSM_SHA="$(sha256sum "$KMSTOOL_LIBNSM" | awk '{print $1}')"
IMAGE_TAG="medseal-enclave:${DOCKERFILE_SHA:0:12}-${REQUIREMENTS_SHA:0:12}-${KMSTOOL_CLI_SHA:0:12}"

echo "[1/4] Pulling pinned base image..."
docker pull "$PINNED_BASE_IMAGE"

echo "[2/4] Building Docker image without cache..."
docker build \
    --no-cache \
    --build-arg "PYTHON_VERSION=$PYTHON_VERSION" \
    -t "$IMAGE_TAG" \
    "$ENCLAVE_DIR"

echo "[3/4] Converting to EIF..."
nitro-cli build-enclave \
    --docker-uri "$IMAGE_TAG" \
    --output-file "$OUTPUT_DIR/medseal.eif"

EIF_SHA="$(sha256sum "$OUTPUT_DIR/medseal.eif" | awk '{print $1}')"

cat > "$OUTPUT_DIR/manifest.json" <<EOF
{
  "artifacts": {
    "eif": {
      "path": "build/medseal.eif",
      "sha256": "$EIF_SHA"
    },
    "dockerfile": {
      "path": "enclave/Dockerfile",
      "sha256": "$DOCKERFILE_SHA"
    },
    "requirements": {
      "path": "enclave/requirements.txt",
      "sha256": "$REQUIREMENTS_SHA"
    },
    "kmstool_enclave_cli": {
      "path": "enclave/bin/kmstool_enclave_cli",
      "sha256": "$KMSTOOL_CLI_SHA"
    },
    "libnsm": {
      "path": "enclave/bin/libnsm.so",
      "sha256": "$KMSTOOL_LIBNSM_SHA"
    }
  },
  "docker": {
    "image_tag": "$IMAGE_TAG",
    "base_image": "$PINNED_BASE_IMAGE",
    "build_args": {
      "PYTHON_VERSION": "$PYTHON_VERSION"
    },
    "no_cache": true
  }
}
EOF

echo "[4/4] PCR measurements:"
nitro-cli describe-eif --eif-path "$OUTPUT_DIR/medseal.eif"

echo ""
echo "=== Build complete ==="
echo "EIF: $OUTPUT_DIR/medseal.eif"
echo "Manifest: $OUTPUT_DIR/manifest.json"
echo ""
echo "Write PCR tfvars with:"
echo "./scripts/extract-pcrs.sh build/medseal.eif > infrastructure/pcrs.auto.tfvars"
