#!/bin/bash
# Build AWS's official kmstool-enclave-cli artifacts for the enclave image.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${MEDSEAL_KMSTOOL_BUILD_DIR:-$PROJECT_DIR/build/kmstool}"
SDK_TAG="${MEDSEAL_KMSTOOL_SDK_TAG:-v0.4.5}"
SDK_DIR="$BUILD_DIR/aws-nitro-enclaves-sdk-c-$SDK_TAG"
IMAGE_TAG="medseal-kmstool-enclave-cli:$SDK_TAG"
ENCLAVE_BIN_DIR="$PROJECT_DIR/enclave/bin"
CONTEXT_PATCH="$SCRIPT_DIR/patches/kmstool-encryption-context.patch"

mkdir -p "$BUILD_DIR" "$ENCLAVE_BIN_DIR"

if [ ! -d "$SDK_DIR/.git" ]; then
    rm -rf "$SDK_DIR"
    git clone --depth 1 --branch "$SDK_TAG" \
        https://github.com/aws/aws-nitro-enclaves-sdk-c.git \
        "$SDK_DIR"
fi

if ! grep -q -- "--encryption-context" "$SDK_DIR/bin/kmstool-enclave-cli/main.c"; then
    patch -d "$SDK_DIR" -p1 < "$CONTEXT_PATCH"
fi

docker build \
    --target kmstool-enclave-cli \
    -t "$IMAGE_TAG" \
    -f "$SDK_DIR/containers/Dockerfile.al2" \
    "$SDK_DIR"

container_id="$(docker create "$IMAGE_TAG")"
cleanup() {
    docker rm "$container_id" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker cp "$container_id:/kmstool_enclave_cli" "$ENCLAVE_BIN_DIR/kmstool_enclave_cli"
docker cp "$container_id:/usr/lib64/libnsm.so" "$ENCLAVE_BIN_DIR/libnsm.so"
chmod 0755 "$ENCLAVE_BIN_DIR/kmstool_enclave_cli" "$ENCLAVE_BIN_DIR/libnsm.so"

sha256sum "$ENCLAVE_BIN_DIR/kmstool_enclave_cli" "$ENCLAVE_BIN_DIR/libnsm.so"
