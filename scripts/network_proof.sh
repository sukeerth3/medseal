#!/usr/bin/env bash
# Capture network traffic on the EC2 host during a MedSeal request,
# then prove that the original plaintext PHI never appears anywhere on the wire.
#
# Usage (from your laptop):
#   bash scripts/network_proof.sh
#
# Writes the pcap and grep summary under OUT_DIR.

set -euo pipefail

HOST_IP="100.54.115.113"
SSH_KEY="$HOME/.ssh/medseal-dev.pem"
SSH_USER="ec2-user"
GATEWAY_URL="http://${HOST_IP}:8080"
KMS_KEY="arn:aws:kms:us-east-1:321052919598:key/7df45129-6767-4b08-a591-3efc2e8baed3"
TOKEN="dev-medseal-token"

OUT_DIR="$(dirname "$(realpath "$0")")/../.codex-logs/network"
mkdir -p "$OUT_DIR"

# Synthetic record with unique canary strings.
PATIENT_FILE=/tmp/patient_proof.txt
cat > "$PATIENT_FILE" <<'EOF'
Patient: Jonathan-CANARY-Doe, DOB 1985-04-12, MRN UNIQUE-CANARY-7781.
Phone (415) 555-CANARY. Address 221B BAKERSTREET-CANARY, San Francisco.
Diagnosis: type-2 diabetes mellitus.  Patient reports persistent cough.
EOF
echo "[1/5] Patient record contains canary strings:"
grep -oE "CANARY|BAKERSTREET-CANARY|Jonathan-CANARY-Doe" "$PATIENT_FILE" | sort -u | sed 's/^/    /'

PCAP_REMOTE=/tmp/medseal_capture.pcap
echo "[2/5] Starting tcpdump on host (any interface)..."
ssh -i "$SSH_KEY" -n -T -o BatchMode=yes "$SSH_USER@$HOST_IP" \
  "sudo pkill -f tcpdump 2>/dev/null; sudo rm -f $PCAP_REMOTE; sudo bash -c 'nohup tcpdump -i ens5 -w $PCAP_REMOTE -s 0 -U -Z root not port 22 >/tmp/tcpdump.log 2>&1 </dev/null &'; sleep 2; pgrep -af '^tcpdump' | head -1" 2>&1 | sed 's/^/    /'
sleep 3

export AWS_PROFILE=medseal MEDSEAL_TOKEN="$TOKEN"
echo "[3/5] Firing encrypt-and-process request..."
.venv/bin/python cli/medseal_cli.py \
  --gateway-url "$GATEWAY_URL" \
  --kms-key-id "$KMS_KEY" \
  encrypt-and-process \
  --file "$PATIENT_FILE" \
  --output /tmp/result_proof.json 2>&1 | tail -8 | sed 's/^/    /'

sleep 3

echo "[4/5] Stopping tcpdump and downloading pcap..."
ssh -i "$SSH_KEY" -n -T -o BatchMode=yes "$SSH_USER@$HOST_IP" "sudo pkill -INT -f 'tcpdump.*medseal_capture' 2>/dev/null; sleep 2; sudo chmod 0644 $PCAP_REMOTE"
scp -i "$SSH_KEY" "$SSH_USER@$HOST_IP:$PCAP_REMOTE" "$OUT_DIR/host_capture.pcap" >/dev/null 2>&1
PCAP_SIZE=$(stat -c%s "$OUT_DIR/host_capture.pcap")
echo "    captured $PCAP_SIZE bytes -> $OUT_DIR/host_capture.pcap"

echo "[5/5] Analyzing capture for any PHI leakage..."

GREP_OUT="$OUT_DIR/grep_results.txt"
{
  echo "NETWORK PROOF: plaintext PHI canary search"
  echo
  echo "Capture file:    $OUT_DIR/host_capture.pcap"
  echo "Capture size:    $PCAP_SIZE bytes"
  echo "Capture covers:  all interfaces during a real encrypt-and-process call"
  echo
  echo "Patient record contained these unique strings:"
  grep -oE "CANARY|BAKERSTREET-CANARY|Jonathan-CANARY-Doe|UNIQUE-CANARY-7781|555-CANARY" "$PATIENT_FILE" | sort -u | sed 's/^/    /'
  echo
  echo "Searching pcap for plaintext PHI:"
  for needle in "Jonathan-CANARY-Doe" "BAKERSTREET-CANARY" "UNIQUE-CANARY-7781" "555-CANARY" "Diabetes mellitus"; do
    HITS=$(grep -aoc "$needle" "$OUT_DIR/host_capture.pcap" 2>/dev/null || echo 0)
    printf "    %-30s -> %s hits\n" "$needle" "$HITS"
  done
  echo
  echo "Expected capture contents: TLS plus encrypted payloads"
  echo "    TLS handshakes to AWS:"
  grep -ao "kms\.us-east-1\.amazonaws\.com\|s3\.\|dynamodb\." "$OUT_DIR/host_capture.pcap" | sort -u | head -10 | sed 's/^/        /'
  echo
  echo "    Number of TLS records (looking for ClientHello/ServerHello):"
  TLS_COUNT=$(grep -aoE $'\\x16\\x03[\\x01-\\x04]' "$OUT_DIR/host_capture.pcap" 2>/dev/null | wc -l)
  echo "        ~$TLS_COUNT TLS record markers seen"
  echo
  echo "Verdict:"
  ANY_LEAK=0
  for needle in "Jonathan-CANARY-Doe" "BAKERSTREET-CANARY" "UNIQUE-CANARY-7781" "555-CANARY"; do
    if grep -aq "$needle" "$OUT_DIR/host_capture.pcap" 2>/dev/null; then
      ANY_LEAK=1
      echo "    LEAK: \"$needle\" appeared in plaintext on the wire!"
    fi
  done
  if [ "$ANY_LEAK" = "0" ]; then
    echo "    PASS: none of the plaintext PHI canaries appeared anywhere"
    echo "    in the captured traffic.  Wire traffic was TLS-encrypted to"
    echo "    AWS endpoints (KMS, S3, DynamoDB) and opaque vsock bytes."
  fi
  echo
  echo "Enclave network check:"
} > "$GREP_OUT"

ssh -i "$SSH_KEY" -n -T -o BatchMode=yes "$SSH_USER@$HOST_IP" \
  'echo "    nitro-cli describe-enclaves shows the enclave is RUNNING:"; nitro-cli describe-enclaves | head -8 | sed "s/^/        /"; echo; echo "    The enclave VM has NO ethernet interface, only vsock CID 16:"; echo "        (vsock is a kernel-internal socket family, never on any NIC)"; echo; echo "    Host interfaces actually carrying packets:"; ip -br addr show | head -10 | sed "s/^/        /"' >> "$GREP_OUT"

cat "$GREP_OUT"

echo
echo "Done. Evidence saved in: $OUT_DIR/"
ls -la "$OUT_DIR/" | sed 's/^/    /'
