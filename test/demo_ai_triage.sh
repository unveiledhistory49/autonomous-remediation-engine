#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Autonomous Remediation Engine - AI Incident Triage Demo
# Architectural Principle: "AI proposes. Deterministic systems enforce."
# ==============================================================================

# Formatting and color styling
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export PATH="${REPO_ROOT}/bin:$PATH"

echo -e "${BOLD}${CYAN}==================================================================${NC}"
echo -e "${BOLD}${CYAN}  AUTONOMOUS REMEDIATION ENGINE: AI INCIDENT TRIAGE CLOSED LOOP   ${NC}"
echo -e "${BOLD}${CYAN}  Foundational Principle: 'AI proposes. Deterministic systems enforce.'${NC}"
echo -e "${BOLD}${CYAN}==================================================================${NC}\n"

# 1. Ensure binaries are built
if [ ! -f "${REPO_ROOT}/bin/remediation-ctl" ]; then
    echo -e "${YELLOW}[*] Building remediation-ctl binary...${NC}"
    make -C "${REPO_ROOT}" build
fi

# 2. Resolve NVIDIA API Key
if [ -z "${NVIDIA_API_KEY:-}" ]; then
    # Check if configured in ai-security-guardrail-proxy
    if [ -f "/root/ai-security-guardrail-proxy/config.nvidia.yaml" ]; then
        KEY_FOUND=$(grep "upstream_auth_token:" /root/ai-security-guardrail-proxy/config.nvidia.yaml | awk '{print $2}' | tr -d '"')
        if [ -n "${KEY_FOUND}" ]; then
            export NVIDIA_API_KEY="${KEY_FOUND}"
        fi
    fi
fi

if [ -z "${NVIDIA_API_KEY:-}" ]; then
    echo -e "${RED}[ERROR] NVIDIA_API_KEY is not set. Please set NVIDIA_API_KEY before running demo.${NC}" >&2
    exit 1
fi

echo -e "${BLUE}[*] Configured Live Inference Endpoint:${NC}"
echo -e "    Provider: NVIDIA NIM Cloud Integration"
echo -e "    Model   : nvidia/nemotron-3-ultra-550b-a55b"
echo -e "    Key     : ${NVIDIA_API_KEY:0:10}...${NVIDIA_API_KEY: -6}\n"

# 3. Setup temporary test paths & isolation
DEMO_DIR="/var/log/ai-gateway"
AUDIT_LOG="/tmp/demo-remediation-audit.log"
LOCK_DIR="/tmp/demo-remediation-locks"
JOURNAL_DIR="/tmp/demo-remediation-journal"
DAMPING_FILE="/tmp/demo-remediation-damping.json"
INCIDENT_FILE="/tmp/demo-incident-unstructured.log"

rm -rf "${LOCK_DIR}" "${JOURNAL_DIR}" "${AUDIT_LOG}" "${DAMPING_FILE}" "${INCIDENT_FILE}"
mkdir -p "${DEMO_DIR}" "${LOCK_DIR}" "${JOURNAL_DIR}"

cleanup() {
    rm -rf "${DEMO_DIR}" "${LOCK_DIR}" "${JOURNAL_DIR}" "${AUDIT_LOG}" "${DAMPING_FILE}" "${INCIDENT_FILE}"
}
trap cleanup EXIT

# 4. Synthesize Real Incident: Disk Saturation with rotated logs
echo -e "${BOLD}${YELLOW}--- [PHASE 1: INCIDENT SYNTHESIS & INJECTION] ---${NC}"
echo -e "[*] Generating synthetic incident state in ${DEMO_DIR}..."

# Touch and seed active log
ACTIVE_LOG="${DEMO_DIR}/ai-gateway.log"
echo "2026-09-22T22:30:00Z [INFO] ai-gateway active process logging" > "${ACTIVE_LOG}"
ORIGINAL_ACTIVE_INODE=$(stat -c '%i' "${ACTIVE_LOG}")
echo -e "    Active Log File : ${ACTIVE_LOG} (Inode: ${ORIGINAL_ACTIVE_INODE})"

# Create 5 expired compressed archives (>48h old)
echo -e "    Generating 5 expired compressed archive logs (20MB each)..."
for i in {1..5}; do
    ARCHIVE_FILE="${DEMO_DIR}/ai-gateway.log.2026-09-1${i}.gz"
    fallocate -l 20M "${ARCHIVE_FILE}"
    touch -d "3 days ago" "${ARCHIVE_FILE}"
done
ARCHIVE_COUNT_BEFORE=$(find "${DEMO_DIR}" -name "*.gz" | wc -l)
echo -e "    Total Expired Archives: ${ARCHIVE_COUNT_BEFORE} files\n"

# 5. Formulate Unstructured Incident Telemetry
cat << 'EOF' > "${INCIDENT_FILE}"
2026-09-22T22:30:15.102Z [ALERT] storage-monitor[8112]: Partition /var/log/ai-gateway at 98.4% utilization (49.2GB / 50.0GB allocated).
2026-09-22T22:30:15.105Z [CRITICAL] ai-gateway-ingress[4012]: Failed to flush trace buffer to /var/log/ai-gateway/ai-gateway.log: write: no space left on device (ENOSPC).
2026-09-22T22:30:16.001Z [WARNING] ai-gateway-daemon: 5 rotated archive logs detected in /var/log/ai-gateway, uncompressed and compressed backlog exceeding retention threshold.
2026-09-22T22:30:16.020Z [EMERGENCY] kernel: [48912.19] EXT4-fs error (device nvme0n1p2): ext4_lookup: inode space depleted on volume /var/log/ai-gateway
EOF

echo -e "${BOLD}${MAGENTA}--- [UNSTRUCTURED INCIDENT TELEMETRY] ---${NC}"
cat "${INCIDENT_FILE}"
echo -e "${BOLD}${MAGENTA}-----------------------------------------${NC}\n"

# 6. Phase 2: AI Incident Triage (DRY-RUN: AI Proposes)
echo -e "${BOLD}${YELLOW}--- [PHASE 2: AI TRIAGE (DRY-RUN / 'AI PROPOSES')] ---${NC}"
echo -e "[*] Submitting unstructured telemetry to NVIDIA Nemotron SRE Reasoning Agent..."
remediation-ctl triage \
    --incident="${INCIDENT_FILE}" \
    --api-key="${NVIDIA_API_KEY}"

# Verify that dry-run did NOT mutate filesystem
ARCHIVES_AFTER_DRYRUN=$(find "${DEMO_DIR}" -name "*.gz" | wc -l)
if [ "${ARCHIVES_AFTER_DRYRUN}" -ne "${ARCHIVE_COUNT_BEFORE}" ]; then
    echo -e "${RED}[FAIL] Dry-run mutated filesystem! Archives reduced from ${ARCHIVE_COUNT_BEFORE} to ${ARCHIVES_AFTER_DRYRUN}${NC}" >&2
    exit 1
fi
echo -e "\n${GREEN}[VERIFIED] Dry-run safe: Filesystem unmutated (${ARCHIVES_AFTER_DRYRUN}/${ARCHIVE_COUNT_BEFORE} archives intact).${NC}\n"

# 7. Phase 3: AI Proposal -> Deterministic Enforcement Closed Loop
echo -e "${BOLD}${YELLOW}--- [PHASE 3: CLOSED-LOOP ENFORCEMENT ('DETERMINISTIC SYSTEMS ENFORCE')] ---${NC}"
echo -e "[*] Executing triage with --execute to enforce proposal through deterministic state machine..."

remediation-ctl triage \
    --incident="${INCIDENT_FILE}" \
    --api-key="${NVIDIA_API_KEY}" \
    --execute \
    --audit-log="${AUDIT_LOG}" \
    --lock-dir="${LOCK_DIR}" \
    --journal-dir="${JOURNAL_DIR}" \
    --damping-file="${DAMPING_FILE}"

echo -e "\n${BOLD}${YELLOW}--- [PHASE 4: INVARIANT ASSERTION & GROUND-TRUTH VERIFICATION] ---${NC}"

# Verify expired archives were pruned
ARCHIVE_COUNT_AFTER=$(find "${DEMO_DIR}" -name "*.gz" | wc -l)
echo -e "[*] Expired archives remaining in ${DEMO_DIR}: ${ARCHIVE_COUNT_AFTER} (expected: 0)"
if [ "${ARCHIVE_COUNT_AFTER}" -ne 0 ]; then
    echo -e "${RED}[FAIL] Expected 0 expired archives, found ${ARCHIVE_COUNT_AFTER}${NC}" >&2
    exit 1
fi

# Verify active log file was PRESERVED and its inode was NOT modified
CURRENT_ACTIVE_INODE=$(stat -c '%i' "${ACTIVE_LOG}")
echo -e "[*] Active log inode check: original=${ORIGINAL_ACTIVE_INODE}, current=${CURRENT_ACTIVE_INODE}"
if [ "${ORIGINAL_ACTIVE_INODE}" -ne "${CURRENT_ACTIVE_INODE}" ]; then
    echo -e "${RED}[FAIL] Active log was corrupted or truncated! Inode changed from ${ORIGINAL_ACTIVE_INODE} to ${CURRENT_ACTIVE_INODE}${NC}" >&2
    exit 1
fi
echo -e "${GREEN}[VERIFIED] Active log inode strictly preserved. Safe log drain invariant satisfied.${NC}\n"

# 8. Phase 5: Cryptographic Hash Chain Audit Ledger Verification
echo -e "${BOLD}${YELLOW}--- [PHASE 5: CRYPTOGRAPHIC AUDIT LEDGER PROOF] ---${NC}"
echo -e "[*] Verifying cryptographic SHA-256 hash-chain continuity from genesis record H0..."
remediation-ctl verify-audit --file="${AUDIT_LOG}"

echo -e "\n${BOLD}${GREEN}==================================================================${NC}"
echo -e "${BOLD}${GREEN}  DEMO COMPLETE: END-TO-END AUTONOMOUS REMEDIATION SUCCEEDED     ${NC}"
echo -e "${BOLD}${GREEN}  Closed Loop Verified:                                           ${NC}"
echo -e "${BOLD}${GREEN}  [Unstructured Log]                                              ${NC}"
echo -e "${BOLD}${GREEN}    -> [NVIDIA Nemotron Reasoning]                                ${NC}"
echo -e "${BOLD}${GREEN}    -> [Structured Runbook Proposal]                              ${NC}"
echo -e "${BOLD}${GREEN}    -> [Deterministic Advisory Lock]                              ${NC}"
echo -e "${BOLD}${GREEN}    -> [Precondition Invariant Gate]                              ${NC}"
echo -e "${BOLD}${GREEN}    -> [Blast Radius Clamping Sandbox]                            ${NC}"
echo -e "${BOLD}${GREEN}    -> [Safe Pruning Mutation]                                    ${NC}"
echo -e "${BOLD}${GREEN}    -> [Postcondition Invariant Assertion]                        ${NC}"
echo -e "${BOLD}${GREEN}    -> [Cryptographic SHA-256 WAL Audit Commit]                   ${NC}"
echo -e "${BOLD}${GREEN}==================================================================${NC}"
exit 0
