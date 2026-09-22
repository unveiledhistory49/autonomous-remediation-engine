#!/usr/bin/env bash
set -euo pipefail

# ANSI color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Ensure bin directory is in PATH and aliases are available
export PATH="${REPO_ROOT}/bin:$PATH"
if [ ! -f "${REPO_ROOT}/bin/autonomous-remediation-ctl" ] && [ -f "${REPO_ROOT}/bin/remediation-ctl" ]; then
    ln -sf "${REPO_ROOT}/bin/remediation-ctl" "${REPO_ROOT}/bin/autonomous-remediation-ctl"
fi

echo -e "${BLUE}===> [CHAOS TEST 3] TLS Expiry & Hot-Reload Simulation...${NC}"
STAGING_DIR="/var/lib/autonomous-remediation/staging"
CERT_DIR="/etc/ssl/certs"
KEY_DIR="/etc/ssl/private"
mkdir -p "${STAGING_DIR}" "${CERT_DIR}" "${KEY_DIR}"

# Isolate damping and test state
rm -f /tmp/remediation-damping.json
rm -rf /tmp/remediation-locks/

cleanup() {
    rm -f "${STAGING_DIR}/tls.crt" "${STAGING_DIR}/tls.key"
    rm -f "${CERT_DIR}/ai-gateway.crt" "${KEY_DIR}/ai-gateway.key"
    rm -f /tmp/remediation-damping.json
}
trap cleanup EXIT

# 1. Generate an expiring certificate (valid for 2 days)
echo "Generating expiring certificate (2 days validity)..."
openssl req -x509 -nodes -days 2 -newkey rsa:2048 \
    -keyout "${KEY_DIR}/ai-gateway.key" \
    -out "${CERT_DIR}/ai-gateway.crt" \
    -subj "/CN=127.0.0.1" 2>/dev/null

# 2. Generate a valid replacement certificate (valid for 365 days)
echo "Generating valid replacement certificate in staging (365 days validity)..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${STAGING_DIR}/tls.key" \
    -out "${STAGING_DIR}/tls.crt" \
    -subj "/CN=127.0.0.1" 2>/dev/null

NEW_SERIAL=$(openssl x509 -in "${STAGING_DIR}/tls.crt" -noout -serial | cut -d= -f2)

# 3. Trigger TLS renewal runbook
echo "Executing TLS cert reload runbook..."
autonomous-remediation-ctl run --runbook=tls_cert_renew_internal --target=ai-gateway

# 4. Assert deployed certificate serial matches replacement serial
ACTIVE_SERIAL=$(openssl x509 -in "${CERT_DIR}/ai-gateway.crt" -noout -serial | cut -d= -f2)

# Case-insensitive comparison of serials
if [ "${ACTIVE_SERIAL,,}" = "${NEW_SERIAL,,}" ]; then
    echo -e "${GREEN}SUCCESS: TLS certificate rotated atomically to serial ${ACTIVE_SERIAL}.${NC}"
    exit 0
else
    echo -e "${RED}FAILED: Serial mismatch! Expected ${NEW_SERIAL}, got ${ACTIVE_SERIAL}${NC}" >&2
    exit 1
fi
