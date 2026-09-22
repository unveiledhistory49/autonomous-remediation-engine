#!/usr/bin/env bash
set -euo pipefail

# ANSI color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}${CYAN}   AUTONOMOUS REMEDIATION ENGINE: LAYER 4 CHAOS VERIFICATION SUITE      ${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "Repository Root : ${REPO_ROOT}"
echo -e "Execution Time  : $(date -u +%FT%TZ)"
echo -e "Platform / Arch : $(uname -s) $(uname -m)"
echo ""

# 1. Build binaries if missing
mkdir -p "${REPO_ROOT}/bin"
export PATH="${REPO_ROOT}/bin:$PATH"

if [ ! -f "${REPO_ROOT}/bin/remediation-ctl" ] || [ ! -f "${REPO_ROOT}/bin/remediation-daemon" ]; then
    echo -e "${YELLOW}Binaries missing. Compiling with pure Go standard library...${NC}"
    (
        cd "${REPO_ROOT}"
        CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/remediation-daemon ./cmd/remediation-daemon
        CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/remediation-ctl ./cmd/remediation-ctl
    )
    echo -e "${GREEN}Build complete: bin/remediation-daemon, bin/remediation-ctl${NC}"
    echo ""
fi

# Ensure alias autonomous-remediation-ctl exists
ln -sf "${REPO_ROOT}/bin/remediation-ctl" "${REPO_ROOT}/bin/autonomous-remediation-ctl"

# Ensure test scripts are executable
chmod +x "${SCRIPT_DIR}"/test_*.sh

TESTS=(
    "test_disk_drain.sh:Chaos Test 1 (Disk Volume Saturation & Auto-Drain)"
    "test_deadlock_recovery.sh:Chaos Test 2 (Process Deadlock & SIGKILL Escalation)"
    "test_tls_rotation.sh:Chaos Test 3 (TLS Cert Expiry & Hot-Reload)"
    "test_config_rollback.sh:Chaos Test 4 (Corrupted Config & LKG Rollback)"
)

PASSED=0
FAILED=0
RESULTS=()

for entry in "${TESTS[@]}"; do
    SCRIPT_NAME="${entry%%:*}"
    TEST_DESC="${entry#*:}"
    SCRIPT_PATH="${SCRIPT_DIR}/${SCRIPT_NAME}"

    echo -e "${BOLD}------------------------------------------------------------------------${NC}"
    echo -e "${BOLD}Running: ${TEST_DESC}${NC}"
    echo -e "Script : ${SCRIPT_PATH}"
    echo -e "${BOLD}------------------------------------------------------------------------${NC}"

    T_START=$(date +%s%N)
    if "${SCRIPT_PATH}"; then
        T_ELAPSED=$(( ($(date +%s%N) - T_START) / 1000000 ))
        echo -e "${GREEN}✓ ${TEST_DESC} [PASSED] (${T_ELAPSED}ms)${NC}\n"
        PASSED=$((PASSED + 1))
        RESULTS+=("${GREEN}PASS${NC} | ${TEST_DESC} | ${T_ELAPSED}ms")
    else
        T_ELAPSED=$(( ($(date +%s%N) - T_START) / 1000000 ))
        echo -e "${RED}✗ ${TEST_DESC} [FAILED] (${T_ELAPSED}ms)${NC}\n"
        FAILED=$((FAILED + 1))
        RESULTS+=("${RED}FAIL${NC} | ${TEST_DESC} | ${T_ELAPSED}ms")
    fi
done

echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}${CYAN}                     CHAOS TEST EXECUTION SUMMARY                       ${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
for r in "${RESULTS[@]}"; do
    echo -e "  [${r}]"
done
echo -e "${BOLD}------------------------------------------------------------------------${NC}"
echo -e "Total: $((PASSED + FAILED)) | Passed: ${GREEN}${PASSED}${NC} | Failed: ${RED}${FAILED}${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"

if [ "${FAILED}" -gt 0 ]; then
    echo -e "${RED}FAILURE: ${FAILED} chaos verification tests failed!${NC}" >&2
    exit 1
else
    echo -e "${GREEN}SUCCESS: All ${PASSED} chaos verification tests passed with 100% invariant adherence!${NC}"
    exit 0
fi
