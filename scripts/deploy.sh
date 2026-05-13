#!/bin/bash
# Deploy MedSeal artifacts to an already-provisioned Nitro Enclaves EC2 host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EC2_FILES_DIR="$PROJECT_DIR/infrastructure/modules/ec2/files"

EIF_PATH="${MEDSEAL_EIF_PATH:-$PROJECT_DIR/build/medseal.eif}"
GATEWAY_JAR="${MEDSEAL_GATEWAY_JAR:-$PROJECT_DIR/gateway/target/gateway-1.0.0.jar}"
ENCLAVE_CLIENT_SRC="${MEDSEAL_ENCLAVE_CLIENT_SRC:-$PROJECT_DIR/enclave/src}"
SSH_HOST="${MEDSEAL_DEPLOY_HOST:-}"
SSH_USER="${MEDSEAL_SSH_USER:-ec2-user}"
SSH_PORT="${MEDSEAL_SSH_PORT:-22}"
REMOTE_DIR="${MEDSEAL_REMOTE_STAGING_DIR:-/tmp/medseal-deploy}"
MEDSEAL_ENCLAVE_CLIENT_PATH="${MEDSEAL_ENCLAVE_CLIENT_PATH:-/opt/medseal/enclave}"
ENCLAVE_CID="${MEDSEAL_ENCLAVE_CID:-16}"
ENCLAVE_CPU_COUNT="${MEDSEAL_ENCLAVE_CPU_COUNT:-2}"
ENCLAVE_MEMORY_MIB="${MEDSEAL_ENCLAVE_MEMORY_MIB:-4096}"
MEDSEAL_ENCLAVE_CID="$ENCLAVE_CID"

MEDSEAL_ENV="${MEDSEAL_ENV:-production}"
SPRING_PROFILES_ACTIVE="${SPRING_PROFILES_ACTIVE:-prod}"
MEDSEAL_AWS_REGION="${MEDSEAL_AWS_REGION:-${AWS_REGION:-us-east-1}}"
AWS_REGION="${AWS_REGION:-$MEDSEAL_AWS_REGION}"
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-$MEDSEAL_AWS_REGION}"
if [[ "$MEDSEAL_ENV" == "development" || ",$SPRING_PROFILES_ACTIVE," == *",dev,"* ]]; then
    IS_DEVELOPMENT_DEPLOYMENT=true
    DEFAULT_TLS_ENABLED=false
else
    IS_DEVELOPMENT_DEPLOYMENT=false
    DEFAULT_TLS_ENABLED=true
fi
MEDSEAL_TLS_ENABLED="${MEDSEAL_TLS_ENABLED:-$DEFAULT_TLS_ENABLED}"
MEDSEAL_ENCLAVE_USE_TCP_FALLBACK="${MEDSEAL_ENCLAVE_USE_TCP_FALLBACK:-false}"
MEDSEAL_TLS_KEYSTORE="${MEDSEAL_TLS_KEYSTORE:-}"
MEDSEAL_TLS_KEYSTORE_PASSWORD="${MEDSEAL_TLS_KEYSTORE_PASSWORD:-}"
MEDSEAL_TLS_KEYSTORE_TYPE="${MEDSEAL_TLS_KEYSTORE_TYPE:-PKCS12}"
MEDSEAL_JWT_ISSUER_URI="${MEDSEAL_JWT_ISSUER_URI:-}"
MEDSEAL_JWT_JWK_SET_URI="${MEDSEAL_JWT_JWK_SET_URI:-}"

if [ "$IS_DEVELOPMENT_DEPLOYMENT" = true ]; then
    MEDSEAL_DEV_TOKEN="${MEDSEAL_DEV_TOKEN:-dev-medseal-token}"
    MEDSEAL_DEV_PRINCIPAL="${MEDSEAL_DEV_PRINCIPAL:-dev-user}"
fi

die() {
    echo "ERROR: $*" >&2
    exit 1
}

require_file() {
    local path="$1"
    [ -f "$path" ] || die "Required file not found: $path"
}

require_dir() {
    local path="$1"
    [ -d "$path" ] || die "Required directory not found: $path"
}

require_env() {
    local name="$1"
    [ -n "${!name:-}" ] || die "Set $name from CI secrets or the deployment environment"
}

quote_systemd_value() {
    local value="$1"
    [[ "$value" != *$'\n'* ]] || die "Environment values must not contain newlines"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '"%s"' "$value"
}

write_env_var() {
    local name="$1"
    local value="${!name:-}"
    [ -n "$value" ] || return 0
    printf '%s=%s\n' "$name" "$(quote_systemd_value "$value")"
}

remote_quote() {
    printf "%q" "$1"
}

[ -n "$SSH_HOST" ] || die "Set MEDSEAL_DEPLOY_HOST to the EC2 public DNS name or IP"
require_file "$EIF_PATH"
require_file "$GATEWAY_JAR"
require_dir "$ENCLAVE_CLIENT_SRC"
require_file "$EC2_FILES_DIR/vsock-proxy.yaml"
require_file "$EC2_FILES_DIR/medseal-kms-proxy.service"
require_file "$EC2_FILES_DIR/medseal-gateway.service"

require_env MEDSEAL_KMS_KEY_ID
require_env MEDSEAL_S3_BUCKET_NAME
require_env MEDSEAL_DYNAMODB_TABLE_NAME

if [ "$MEDSEAL_ENCLAVE_USE_TCP_FALLBACK" != "false" ]; then
    die "MEDSEAL_ENCLAVE_USE_TCP_FALLBACK must be false for remote deployments"
fi

if [ "$IS_DEVELOPMENT_DEPLOYMENT" = true ]; then
    [ "${MEDSEAL_ALLOW_INSECURE_DEMO:-}" = "true" ] || die \
        "Development/demo deployments expose HTTP and dev bearer auth; set MEDSEAL_ALLOW_INSECURE_DEMO=true to continue"
else
    [ "$MEDSEAL_TLS_ENABLED" = "true" ] || die "MEDSEAL_TLS_ENABLED must be true outside development/demo deployments"
    require_env MEDSEAL_TLS_KEYSTORE
    require_env MEDSEAL_TLS_KEYSTORE_PASSWORD
    if [ -z "$MEDSEAL_JWT_ISSUER_URI" ] && [ -z "$MEDSEAL_JWT_JWK_SET_URI" ]; then
        die "Set MEDSEAL_JWT_ISSUER_URI or MEDSEAL_JWT_JWK_SET_URI from the deployment environment"
    fi
fi

if [ -n "${MEDSEAL_TLS_KEYSTORE_SOURCE:-}" ]; then
    require_file "$MEDSEAL_TLS_KEYSTORE_SOURCE"
fi

SSH_OPTS=(-p "$SSH_PORT" -o StrictHostKeyChecking=accept-new)
SCP_OPTS=(-P "$SSH_PORT" -o StrictHostKeyChecking=accept-new)
if [ -n "${MEDSEAL_SSH_KEY:-}" ]; then
    require_file "$MEDSEAL_SSH_KEY"
    SSH_OPTS+=(-i "$MEDSEAL_SSH_KEY")
    SCP_OPTS+=(-i "$MEDSEAL_SSH_KEY")
fi

ENV_FILE="$(mktemp)"
ENCLAVE_CLIENT_ARCHIVE="$(mktemp)"
trap 'rm -f "$ENV_FILE" "$ENCLAVE_CLIENT_ARCHIVE"' EXIT

tar --exclude='__pycache__' --exclude='*.pyc' \
    -C "$(dirname "$ENCLAVE_CLIENT_SRC")" \
    -czf "$ENCLAVE_CLIENT_ARCHIVE" \
    "$(basename "$ENCLAVE_CLIENT_SRC")"

{
    write_env_var MEDSEAL_ENV
    write_env_var SPRING_PROFILES_ACTIVE
    write_env_var MEDSEAL_AWS_REGION
    write_env_var AWS_REGION
    write_env_var AWS_DEFAULT_REGION
    write_env_var MEDSEAL_KMS_KEY_ID
    write_env_var MEDSEAL_KMS_KEY_ID_ALLOWLIST_REGEX
    write_env_var MEDSEAL_ENCLAVE_CID
    write_env_var MEDSEAL_ENCLAVE_CLIENT_PATH
    write_env_var MEDSEAL_ENCLAVE_USE_TCP_FALLBACK
    write_env_var MEDSEAL_S3_BUCKET_NAME
    write_env_var MEDSEAL_DYNAMODB_TABLE_NAME
    write_env_var MEDSEAL_DYNAMODB_IN_MEMORY
    write_env_var MEDSEAL_TLS_ENABLED
    write_env_var MEDSEAL_TLS_KEYSTORE
    write_env_var MEDSEAL_TLS_KEYSTORE_PASSWORD
    write_env_var MEDSEAL_TLS_KEYSTORE_TYPE
    write_env_var MEDSEAL_CORS_ALLOWED_ORIGINS
    write_env_var MEDSEAL_JWT_ISSUER_URI
    write_env_var MEDSEAL_JWT_JWK_SET_URI
    write_env_var MEDSEAL_DEV_TOKEN
    write_env_var MEDSEAL_DEV_PRINCIPAL
} > "$ENV_FILE"

TARGET="$SSH_USER@$SSH_HOST"
REMOTE_DIR_Q="$(remote_quote "$REMOTE_DIR")"
ENCLAVE_CID_Q="$(remote_quote "$ENCLAVE_CID")"
ENCLAVE_CPU_COUNT_Q="$(remote_quote "$ENCLAVE_CPU_COUNT")"
ENCLAVE_MEMORY_MIB_Q="$(remote_quote "$ENCLAVE_MEMORY_MIB")"
MEDSEAL_ENCLAVE_CLIENT_PATH_Q="$(remote_quote "$MEDSEAL_ENCLAVE_CLIENT_PATH")"
MEDSEAL_TLS_KEYSTORE_Q="$(remote_quote "$MEDSEAL_TLS_KEYSTORE")"
MEDSEAL_TLS_ENABLED_Q="$(remote_quote "$MEDSEAL_TLS_ENABLED")"

echo "Uploading MedSeal artifacts to $TARGET"
ssh "${SSH_OPTS[@]}" "$TARGET" "rm -rf $REMOTE_DIR_Q && mkdir -p $REMOTE_DIR_Q"
scp "${SCP_OPTS[@]}" "$EIF_PATH" "$TARGET:$REMOTE_DIR/medseal.eif"
scp "${SCP_OPTS[@]}" "$GATEWAY_JAR" "$TARGET:$REMOTE_DIR/gateway.jar"
scp "${SCP_OPTS[@]}" "$ENCLAVE_CLIENT_ARCHIVE" "$TARGET:$REMOTE_DIR/enclave-client-src.tgz"
scp "${SCP_OPTS[@]}" "$EC2_FILES_DIR/vsock-proxy.yaml" "$TARGET:$REMOTE_DIR/vsock-proxy.yaml"
scp "${SCP_OPTS[@]}" "$EC2_FILES_DIR/medseal-kms-proxy.service" "$TARGET:$REMOTE_DIR/medseal-kms-proxy.service"
scp "${SCP_OPTS[@]}" "$EC2_FILES_DIR/medseal-gateway.service" "$TARGET:$REMOTE_DIR/medseal-gateway.service"
scp "${SCP_OPTS[@]}" "$ENV_FILE" "$TARGET:$REMOTE_DIR/gateway.env"

if [ -n "${MEDSEAL_TLS_KEYSTORE_SOURCE:-}" ]; then
    scp "${SCP_OPTS[@]}" "$MEDSEAL_TLS_KEYSTORE_SOURCE" "$TARGET:$REMOTE_DIR/tls-keystore"
fi

ssh "${SSH_OPTS[@]}" "$TARGET" <<REMOTE
set -euo pipefail

REMOTE_DIR=$REMOTE_DIR_Q
ENCLAVE_CID=$ENCLAVE_CID_Q
ENCLAVE_CPU_COUNT=$ENCLAVE_CPU_COUNT_Q
ENCLAVE_MEMORY_MIB=$ENCLAVE_MEMORY_MIB_Q
MEDSEAL_ENCLAVE_CLIENT_PATH=$MEDSEAL_ENCLAVE_CLIENT_PATH_Q
MEDSEAL_TLS_KEYSTORE=$MEDSEAL_TLS_KEYSTORE_Q
MEDSEAL_TLS_ENABLED=$MEDSEAL_TLS_ENABLED_Q

sudo install -d -m 0755 /etc/vsock-proxy /etc/medseal /opt/medseal
sudo install -d -o ec2-user -g ec2-user -m 0755 /opt/medseal

sudo install -m 0644 "\$REMOTE_DIR/vsock-proxy.yaml" /etc/vsock-proxy/medseal.yaml
sudo install -m 0644 "\$REMOTE_DIR/medseal-kms-proxy.service" /etc/systemd/system/medseal-kms-proxy.service
sudo install -m 0644 "\$REMOTE_DIR/medseal-gateway.service" /etc/systemd/system/medseal-gateway.service
sudo install -o ec2-user -g ec2-user -m 0644 "\$REMOTE_DIR/medseal.eif" /opt/medseal/medseal.eif
sudo install -o ec2-user -g ec2-user -m 0644 "\$REMOTE_DIR/gateway.jar" /opt/medseal/gateway.jar
sudo rm -rf "\$MEDSEAL_ENCLAVE_CLIENT_PATH"
sudo install -d -o ec2-user -g ec2-user -m 0755 "\$MEDSEAL_ENCLAVE_CLIENT_PATH"
sudo tar -xzf "\$REMOTE_DIR/enclave-client-src.tgz" -C "\$MEDSEAL_ENCLAVE_CLIENT_PATH"
sudo chown -R ec2-user:ec2-user "\$MEDSEAL_ENCLAVE_CLIENT_PATH"
sudo install -m 0600 "\$REMOTE_DIR/gateway.env" /etc/medseal/gateway.env

if [ -f "\$REMOTE_DIR/tls-keystore" ]; then
    sudo install -d -m 0750 -o root -g ec2-user "\$(dirname "\$MEDSEAL_TLS_KEYSTORE")"
    sudo install -m 0640 -o root -g ec2-user "\$REMOTE_DIR/tls-keystore" "\$MEDSEAL_TLS_KEYSTORE"
fi

sudo systemd-analyze verify /etc/systemd/system/medseal-kms-proxy.service /etc/systemd/system/medseal-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl enable medseal-kms-proxy.service medseal-gateway.service
sudo systemctl restart medseal-kms-proxy.service

sudo nitro-cli terminate-enclave --all >/dev/null 2>&1 || true
sudo nitro-cli run-enclave \
    --eif-path /opt/medseal/medseal.eif \
    --enclave-cid "\$ENCLAVE_CID" \
    --cpu-count "\$ENCLAVE_CPU_COUNT" \
    --memory "\$ENCLAVE_MEMORY_MIB"

sudo systemctl restart medseal-gateway.service
sudo systemctl is-active --quiet nitro-enclaves-allocator.service
sudo systemctl is-active --quiet medseal-kms-proxy.service
sudo systemctl is-active --quiet medseal-gateway.service

if [ "\$MEDSEAL_TLS_ENABLED" = "false" ]; then
    for attempt in \$(seq 1 30); do
        if curl -fsS http://127.0.0.1:8080/api/v1/health | grep -q '"status":"UP"'; then
            break
        fi
        if [ "\$attempt" -eq 30 ]; then
            echo "Gateway health check did not become UP" >&2
            exit 1
        fi
        sleep 2
    done
fi

sudo nitro-cli describe-enclaves

rm -rf "\$REMOTE_DIR"
REMOTE

echo "MedSeal artifacts deployed and services validated on $TARGET"
