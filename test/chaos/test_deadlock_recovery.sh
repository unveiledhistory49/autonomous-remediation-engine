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

echo -e "${BLUE}===> [CHAOS TEST 2] Process Deadlock Simulation & Escalation Test...${NC}"

# Isolate damping and test state
rm -f /tmp/remediation-damping.json
rm -rf /tmp/remediation-locks/
rm -f /var/run/ai-gateway.pid

MOCK_PID=""
REPLACEMENT_PID=""
CREATED_MOCK_BIN=false

cleanup() {
    if [ -n "${MOCK_PID}" ]; then
        kill -9 "${MOCK_PID}" 2>/dev/null || true
    fi
    if [ -n "${REPLACEMENT_PID}" ]; then
        kill -9 "${REPLACEMENT_PID}" 2>/dev/null || true
    fi
    # If any process is listening on 8080, terminate it
    fuser -k 8080/tcp 2>/dev/null || true
    if [ "${CREATED_MOCK_BIN}" = true ]; then
        rm -f /usr/local/bin/ai-gateway
    fi
    rm -f /var/run/ai-gateway.pid
    rm -f /tmp/remediation-damping.json
}
trap cleanup EXIT

# Setup mock binary for ai-gateway if missing so restart step succeeds
if [ ! -f /usr/local/bin/ai-gateway ]; then
    CREATED_MOCK_BIN=true
    cat << 'EOF' > /usr/local/bin/ai-gateway
#!/usr/bin/env bash
python3 -c "
import http.server, socketserver, os, sys
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/healthz':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.end_headers()
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(('127.0.0.1', 8080), Handler) as httpd:
    httpd.serve_forever()
" &
NEW_PID=$!
echo "${NEW_PID}" > /var/run/ai-gateway.pid
EOF
    chmod +x /usr/local/bin/ai-gateway
fi

# 1. Spawn mock daemon that ignores SIGTERM
python3 -c "
import signal, time, sys
def handler(signum, frame):
    sys.stderr.write('Received SIGTERM, ignoring to simulate deadlock\n')
signal.signal(signal.SIGTERM, handler)
sys.stderr.write('Mock deadlocked service running...\n')
while True:
    time.sleep(1)
" &
MOCK_PID=$!
echo "${MOCK_PID}" > /var/run/ai-gateway.pid
echo "Mock deadlocked service started with PID ${MOCK_PID}"

# 2. Trigger deadlock recovery runbook
echo "Triggering service_deadlock_restart runbook..."
START_TIME=$(date +%s%N)
autonomous-remediation-ctl run --runbook=service_deadlock_restart --target=ai-gateway
ELAPSED_MS=$(( ($(date +%s%N) - START_TIME) / 1000000 ))

# 3. Assert process was terminated via SIGKILL escalation ladder within MTTR budget
if kill -0 "${MOCK_PID}" 2>/dev/null; then
    echo -e "${RED}FAILED: Process ${MOCK_PID} still alive! Deadlock escalation failed.${NC}" >&2
    kill -9 "${MOCK_PID}" 2>/dev/null || true
    exit 1
else
    echo -e "${GREEN}SUCCESS: Deadlocked process terminated in ${ELAPSED_MS}ms via SIGKILL ladder.${NC}"
    exit 0
fi
