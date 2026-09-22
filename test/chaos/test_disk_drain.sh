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

echo -e "${BLUE}===> [CHAOS TEST 1] Disk Saturation Simulation & Auto-Drain Test...${NC}"
TARGET_DIR="/var/log/ai-gateway"
mkdir -p "${TARGET_DIR}"

# Isolate damping and test state
rm -f /tmp/remediation-damping.json
rm -rf /tmp/remediation-locks/

# Cleanup on exit
cleanup() {
    rm -rf "${TARGET_DIR}"
    rm -f /tmp/remediation-damping.json
}
trap cleanup EXIT

# 1. Generate 5 synthetic expired rotated archives (older than 48 hours)
echo "Generating 5 expired compressed log files (200MB each)..."
for i in {1..5}; do
    FILE="${TARGET_DIR}/ai-gateway.log.2026-09-1${i}.gz"
    fallocate -l 200M "${FILE}"
    touch -d "3 days ago" "${FILE}"
done

# 2. Touch active log file (must NOT be touched or pruned)
touch "${TARGET_DIR}/ai-gateway.log"
echo "2026-09-22 active log payload" > "${TARGET_DIR}/ai-gateway.log"
ACTIVE_INODE=$(stat -c '%i' "${TARGET_DIR}/ai-gateway.log")

# 3. Trigger disk log drain runbook via CLI
echo "Executing autonomous remediation disk drain..."
autonomous-remediation-ctl run --runbook=disk_cleanup_var_log --target=/var/log/ai-gateway

# 4. Verify postconditions
REMAINING_ARCHIVES=$(find "${TARGET_DIR}" -name "*.gz" | wc -l)
CURRENT_ACTIVE_INODE=$(stat -c '%i' "${TARGET_DIR}/ai-gateway.log")

if [ "${REMAINING_ARCHIVES}" -eq 0 ] && [ "${ACTIVE_INODE}" -eq "${CURRENT_ACTIVE_INODE}" ]; then
    echo -e "${GREEN}SUCCESS: Expired logs pruned. Active log preserved. Invariants verified.${NC}"
    exit 0
else
    echo -e "${RED}FAILED: Invariants violated! Remaining archives: ${REMAINING_ARCHIVES}, Active inode: ${ACTIVE_INODE} vs ${CURRENT_ACTIVE_INODE}${NC}" >&2
    exit 1
fi
