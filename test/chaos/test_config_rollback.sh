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

echo -e "${BLUE}===> [CHAOS TEST 4] Corrupted Configuration Rollback Simulation...${NC}"
CONFIG_DIR="/etc/ai-gateway"
LKG_DIR="/var/lib/autonomous-remediation/lkg"
mkdir -p "${CONFIG_DIR}" "${LKG_DIR}"

# Isolate damping and test state
rm -f /tmp/remediation-damping.json
rm -rf /tmp/remediation-locks/

cleanup() {
    rm -rf "${CONFIG_DIR}"
    rm -rf "${LKG_DIR}"
    rm -f /tmp/remediation-damping.json
}
trap cleanup EXIT

# 1. Establish verified Last-Known-Good (LKG) configuration
cat << 'EOF' > "${LKG_DIR}/ai-gateway.config.yaml"
server:
  host: 127.0.0.1
  port: 8080
  timeout_seconds: 30
EOF

cp "${LKG_DIR}/ai-gateway.config.yaml" "${CONFIG_DIR}/config.yaml"
LKG_HASH=$(sha256sum "${LKG_DIR}/ai-gateway.config.yaml" | awk '{print $1}')

# 2. Inject corrupted configuration (malformed syntax)
cat << 'EOF' > "${CONFIG_DIR}/config.yaml"
server:
  host: 127.0.0.1
  port: MALFORMED_PORT_TRIGGERING_SYNTAX_ERROR: [unterminated
EOF

echo "Corrupted config injected into ${CONFIG_DIR}/config.yaml"

# 3. Trigger configuration rollback runbook
echo "Invoking configuration rollback runbook..."
autonomous-remediation-ctl run --runbook=config_rollback --target=ai-gateway

# 4. Assert active configuration was reverted to LKG hash
ACTIVE_HASH=$(sha256sum "${CONFIG_DIR}/config.yaml" | awk '{print $1}')
if [ "${ACTIVE_HASH}" = "${LKG_HASH}" ]; then
    echo -e "${GREEN}SUCCESS: Corrupted config rolled back to LKG hash ${LKG_HASH}.${NC}"
    exit 0
else
    echo -e "${RED}FAILED: Rollback failed! Current hash ${ACTIVE_HASH} != LKG ${LKG_HASH}${NC}" >&2
    exit 1
fi
