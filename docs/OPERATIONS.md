# Autonomous Remediation Engine: Operations, Deployment & Runbook Manual

## 1. Overview & Operational Invariants

This manual defines the deployment architecture, kernel-level host tuning, process supervision lifecycles, and automated runbook procedures for the Autonomous Remediation Engine (`autonomous-remediation-engine`).

Compliant with [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md) and [08-autonomous-remediation-engine.md](file:///root/company-project-specs/08-autonomous-remediation-engine.md), this daemon provides autonomous, deterministic infrastructure recovery across Linux ARM64 systems. It monitors, manages, and remediates faults for critical local platform services, specifically the [ai-gateway](file:///root/company-project-specs/01-ai-gateway.md) and the [ai-security-guardrail-proxy](file:///root/company-project-specs/09-ai-security-guardrail-proxy.md). Formal reliability boundaries and metrics are defined in [FAILURE-MODES.md](file:///root/autonomous-remediation-engine/docs/FAILURE-MODES.md) and [SLO.md](file:///root/autonomous-remediation-engine/docs/SLO.md).

### 1.1. Core Operational Invariants

The engine operates under five fundamental operational invariants:

1. **Zero External Daemon Dependencies**:
   The engine runs as an autonomous, self-contained single Go 1.23+ statically linked binary (`CGO_ENABLED=0`). It requires **no Redis, no PostgreSQL, no etcd, no Docker daemon, and no external cloud SaaS**. All state machines, flap counters, rate limiters, and lock tables execute strictly in-process and persist to local POSIX filesystems.
2. **"AI Proposes. Deterministic Systems Enforce."**:
   Probabilistic models or LLM agents may classify noisy logs or propose candidate remediation plans. However, **zero unverified actions are ever executed**. All host mutations are guarded by deterministic preconditions, blast-radius clamps, and postcondition verification barriers.
3. **100% Postcondition Verification Invariant**:
   An action is incomplete and rejected until the system verifies its intended outcome against ground-truth operating system states (`/proc`, `statvfs`, TCP loopback probes). Blind script execution ($?=0$ trust) is architecturally forbidden.
4. **Non-Blocking Kernel Lock Mutual Exclusion**:
   Every managed target process or subsystem possesses a dedicated kernel advisory file lock (`flock(2)`/`fcntl(2)`). If a lock cannot be acquired non-blockingly, the engine fails fast to eliminate lock deadlocks and re-entrant execution loops.
5. **Two-Phase Write-Ahead Rollback Journaling**:
   Before any destructive mutation is applied to files or processes, the inverse compensating operation is recorded to an atomic Write-Ahead Log (WAL) on disk and flushed via `fsync(2)`. Any postcondition failure triggers an immediate automated rollback.

---

## 2. Deployment Architecture & Host Configuration

### 2.1. Target Environment & Compilation
The remediation engine is built as a pure, statically linked binary targeting Linux ARM64 (`aarch64`):

```bash
# Compilation command for hardened static binary
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
    -trimpath \
    -ldflags="-s -w -X 'main.Version=1.0.0' -X 'main.BuildTime=$(date -u +%FT%TZ)' -extldflags '-static'" \
    -o /usr/local/bin/autonomous-remediation-engine ./cmd/daemon
```

### 2.2. Directory Structure & Permissions
The daemon enforces strict POSIX ownership and least-privilege permissions:

```
/etc/autonomous-remediation/
├── config.yaml                     (0640, root:remediation) - Static configuration & runbook catalog
└── certs/                          (0600, root:remediation) - HMAC audit keys

/var/run/remediation/               (0750, remediation:remediation) - Lock coordination directory
├── ai-gateway.lock                 (0600, remediation:remediation) - Target advisory flock
├── guardrail-proxy.lock            (0600, remediation:remediation) - Target advisory flock
└── disk-drain.lock                 (0600, remediation:remediation) - Disk drain mutual exclusion lock

/var/lib/autonomous-remediation/    (0700, remediation:remediation) - State persistence & journal
├── journal/                        (0700, remediation:remediation) - Active WAL transaction journals
│   └── 20260922-tx-00142.wal       (0600, remediation:remediation) - Write-ahead rollback log
├── lkg/                            (0700, remediation:remediation) - Last-Known-Good configuration snapshots
│   ├── ai-gateway.config.yaml      (0600, remediation:remediation) - Verified LKG config
│   └── guardrail-proxy.yaml        (0600, remediation:remediation) - Verified LKG config
└── audit/                          (0700, remediation:remediation) - Cryptographic audit ledger
    └── audit.wal                   (0600, remediation:remediation) - SHA-256 HMAC hash-chained log
```

### 2.3. Hardened systemd Production Service Unit
File location: `/etc/systemd/system/autonomous-remediation.service`

```ini
[Unit]
Description=Autonomous Remediation Engine Daemon
Documentation=file:///root/autonomous-remediation-engine/docs/OPERATIONS.md
After=network.target local-fs.target
Wants=local-fs.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/var/lib/autonomous-remediation
ExecStart=/usr/local/bin/autonomous-remediation-engine --config=/etc/autonomous-remediation/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=15s
Restart=always
RestartSec=2s

# File descriptor and execution bounds
LimitNOFILE=32768
LimitNPROC=16384
LimitMEMLOCK=infinity

# Linux Security Hardening Directives
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateTmp=yes
PrivateDevices=no
NoNewPrivileges=no
CapabilityBoundingSet=CAP_KILL CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_KILL CAP_DAC_OVERRIDE CAP_SYS_PTRACE

# File system sandboxing
ReadWritePaths=/var/run/remediation /var/lib/autonomous-remediation /var/log/ai-gateway /var/log/guardrail-proxy /etc/ai-gateway /etc/guardrail-proxy
ReadOnlyPaths=/etc/autonomous-remediation /proc /sys

# Environment
Environment="REMEDIATION_ENV=production"
Environment="GODEBUG=madvdontneed=1"
```

---

## 3. Four Core Production Runbooks

The following runbooks represent the four verified deterministic remediation workflows. Each runbook defines explicit **Preconditions**, **Actions**, **Postconditions**, and **Rollback** sequences.

---

### Runbook 1: Disk Volume Saturation & Safe Log Drain

- **Runbook ID**: `RBK-DISK-001`
- **Target Subsystem**: Filesystem Mount `/var/log` or Local Disk Partition
- **Severity**: HIGH
- **Trigger**: Free disk space on `/var/log` falls below $15\%$ (capacity utilization $\ge 85\%$).

#### Preconditions (Must ALL evaluate to TRUE)
1. Mount point capacity check via `statvfs(2)`:
   $$\text{FreeBytes} / \text{TotalBytes} \le 0.15$$
2. Target directory path matches strict whitelist:
   $$\text{Path} \in \{ \text{`/var/log/ai-gateway`}, \text{`/var/log/guardrail-proxy`} \}$$
3. Target candidate files match rotation patterns (`*.log.1`, `*.log.2`, `*.gz`, `*.old`) with `mtime` older than $24\,\text{hours}$.
4. **Active FD Safety Check**: Target candidate file must **NOT** be held open by any active process:
   $$\forall \text{pid} \in \text{ManagedPIDs} : \text{TargetInode} \notin \text{OpenInodes}(\text{pid})$$
5. Advisory lock `/var/run/remediation/disk-drain.lock` acquired via non-blocking `flock(LOCK_EX | LOCK_NB)`.

#### Remediation Actions (Sequential)
1. **Journal Pre-Commit**: Record file list to be purged into transaction WAL `/var/lib/autonomous-remediation/journal/[txid].wal`.
2. **Stage Oldest File Metadata**: Snapshot file inodes, sizes, and timestamps to the journal.
3. **Execute Bounded Deletion**: Remove files in ascending order of `mtime` (oldest first).
   - Hard Blast-Radius Clamp: Maximum $10$ files removed in a single run.
   - Hard Volume Clamp: Maximum $20\,\text{GiB}$ removed in a single pass.
4. **Trigger Active Log Truncate / SIGHUP**: If uncompressed active log exceeds $5\,\text{GiB}$, copy active file tail, truncate original via `truncate(2)`, and issue `SIGHUP` to target process to reopen file descriptors.

#### Postconditions (Ground-Truth Invariants)
1. Disk capacity utilization drops below target threshold:
   $$\text{FreeBytes} / \text{TotalBytes} \ge 0.25 \quad (\text{Capacity} \le 75\%)$$
2. Active service log file exists and is receiving writes:
   $$\Delta \text{mtime}(\text{active.log}) \le 5.0\,\text{s} \quad \text{and} \quad \text{size}(\text{active.log}) > 0$$
3. Target services (`ai-gateway`, `guardrail-proxy`) report operational health (`HTTP 200` on `/healthz`).

#### Rollback Sequence
- If postconditions fail or capacity remains $\ge 85\%$:
  1. Hault deletions immediately.
  2. If an active log was truncated erroneously, restore preserved tail snapshot from `/var/lib/autonomous-remediation/staging/[txid]/`.
  3. Mark transaction as `FAILED_DISK_EXHAUSTION`.
  4. Emit Sev-1 PagerDuty alarm: `CRITICAL_FILESYSTEM_OUT_OF_SPACE_MANUAL_DRAIN_REQUIRED`.

---

### Runbook 2: Service Process Deadlock / Memory Leak Recovery & Safe Restart

- **Runbook ID**: `RBK-PROC-001`
- **Target Services**: `ai-gateway` or `ai-security-guardrail-proxy`
- **Severity**: CRITICAL
- **Trigger**: 3 consecutive synthetic health probe timeouts ($> 3000\,\text{ms}$) on `http://127.0.0.1:8080/healthz` OR memory RSS exceeding $90\%$ of host cgroup allocation.

#### Preconditions (Must ALL evaluate to TRUE)
1. Target service mutual exclusion lock acquired:
   $$\text{AcquireLock}(\text{`/var/run/remediation/ai-gateway.lock`}) == \text{SUCCESS}$$
2. Target PID retrieved from `/var/run/ai-gateway.pid` or systemd manager.
3. `pidfd` handle acquired via `pidfd_open(targetPID, 0)`:
   - Verify process start time in `/proc/[pid]/stat` matches recorded daemon spawn time (prevents PID recycling race condition).
4. Flap penalty counter $P_k(t) < 2500$ (target circuit breaker is **CLOSED** or **HALF-OPEN**).

#### Remediation Actions (Sequential)
1. **Diagnostic Forensics Capture**: Snapshot `/proc/[pid]/status`, `/proc/[pid]/stack`, and top memory mappings to `/var/log/remediation-dumps/[target]-[timestamp].diag`.
2. **Graceful Signal Dispatch**: Issue `SIGTERM` via `pidfd_send_signal(pidfd, SIGTERM)`.
3. **Monotonic Deadline Wait**: Poll target process state every $100\,\text{ms}$ up to $\tau_{\text{term}} = 5.0\,\text{s}$.
4. **Escalation to Forceful Termination**:
   - If process is still present after $5.0\,\text{s}$, issue `SIGKILL` via `pidfd_send_signal(pidfd, SIGKILL)`.
   - Poll for process reaping up to $\tau_{\text{kill}} = 2.0\,\text{s}$.
5. **Kernel D-State Invariant Check**:
   - If process persists after `SIGKILL`, read `/proc/[pid]/wchan`. If wchan indicates kernel sleep (`io_schedule`, `nfs_wait`), abort restart immediately, lock circuit breaker, and page SRE.
6. **Spawn New Process Instance**:
   - Issue systemd D-Bus restart command or execute `/usr/local/bin/ai-gateway --config=/etc/ai-gateway/config.yaml`.
   - Record new PID and spawn timestamp.

#### Postconditions (Ground-Truth Invariants)
1. New process exists and is running:
   $$\text{State}(\text{NewPID}) \in \{ \text{'R'}, \text{'S'} \}$$
2. Network listener active: Socket port 8080 in state `LISTEN` in `/proc/net/tcp`.
3. Health check passes:
   $$\text{HTTPGet}(\text{http://127.0.0.1:8080/healthz}) \to 200\,\text{OK} \quad (\text{latency} < 200\,\text{ms})$$
4. Elapsed time from alert dequeue to health confirmation:
   $$T_{\text{remediation}} \le 5.0\,\text{s}$$

#### Rollback Sequence
- If new process fails to spawn or `/healthz` fails after $5.0\,\text{s}$:
  1. Terminate malfunctioning candidate process.
  2. Restore Last-Known-Good configuration snapshot from `/var/lib/autonomous-remediation/lkg/ai-gateway.config.yaml`.
  3. Re-attempt single spawn.
  4. If second attempt fails: Lock target circuit breaker, mark target as `UNRECOVERABLE_SERVICE_FAILURE`, release lock, and dispatch Sev-1 page.

---

### Runbook 3: TLS Certificate Expiration & Zero-Downtime Reload

- **Runbook ID**: `RBK-TLS-001`
- **Target Services**: `ai-gateway` and `ai-security-guardrail-proxy`
- **Severity**: HIGH
- **Trigger**: Days until TLS certificate expiration $\le 7\,\text{days}$ OR invalid certificate signature detected by local synthetic monitor.

#### Preconditions (Must ALL evaluate to TRUE)
1. Advisory lock `/var/run/remediation/tls-reload.lock` acquired.
2. Staged replacement certificate exists at `/var/lib/autonomous-remediation/staging/tls.crt` and `/var/lib/autonomous-remediation/staging/tls.key`.
3. **Cryptographic Validation Invariant**:
   - Certificate X.509 validity period strictly $> 30\,\text{days}$ from current time.
   - Public key modulus in `tls.crt` matches private key modulus in `tls.key`:
     $$\text{PublicKeyModulus}(\text{tls.crt}) \equiv \text{PrivateKeyModulus}(\text{tls.key})$$
   - Certificate subject matches authorized Fully Qualified Domain Name (FQDN) or IP SAN.

#### Remediation Actions (Sequential)
1. **Atomic Write-Ahead Backup**: Copy current `/etc/ssl/certs/ai-gateway.crt` and `/etc/ssl/private/ai-gateway.key` into `/var/lib/autonomous-remediation/journal/[txid]/`.
2. **Atomic Swap Deployment**:
   - Write staged files to `/etc/ssl/certs/ai-gateway.crt.tmp`.
   - Swap atomically using `renameat2(2)` with `RENAME_EXCHANGE` or atomic POSIX rename:
     $$\text{rename}(\text{ai-gateway.crt.tmp}, \; \text{ai-gateway.crt})$$
3. **Signal Zero-Downtime Reload**:
   - Send `SIGHUP` to target process via `pidfd_send_signal(pidfd, SIGHUP)` to trigger hot configuration/certificate reload without dropping TCP connections.

#### Postconditions (Ground-Truth Invariants)
1. Local TLS Handshake Probe:
   - Establish TLS 1.3 handshake to `127.0.0.1:8443` via Go standard library `crypto/tls`.
2. Assert Peer Certificate Serial Number:
   $$\text{PresentedCertSerialNumber} \equiv \text{StagedCertSerialNumber}$$
3. Zero dropped connections reported in target metrics (`ai_gateway_tls_handshake_errors_total == 0`).

#### Rollback Sequence
- If TLS handshake fails, socket drops, or presented serial number mismatches:
  1. Atomically restore original certificate and key files from journal backup.
  2. Issue `SIGHUP` to target process.
  3. Re-verify TLS handshake against original certificate.
  4. Trip circuit breaker and notify security engineering: `TLS_RELOAD_FAILED_ROLLED_BACK`.

---

### Runbook 4: Corrupted Configuration Rollback to Last-Known-Good (LKG)

- **Runbook ID**: `RBK-CFG-001`
- **Target Services**: `ai-gateway` or `ai-security-guardrail-proxy`
- **Severity**: CRITICAL
- **Trigger**: Target service crash on reload, syntax parse error in log stream, or failed pre-flight configuration validation.

#### Preconditions (Must ALL evaluate to TRUE)
1. Active configuration file at `/etc/ai-gateway/config.yaml` differs from Last-Known-Good (LKG) SHA-256 fingerprint:
   $$\text{SHA256}(\text{ActiveConfig}) \neq \text{SHA256}(\text{LKGConfig})$$
2. Verified LKG backup exists at `/var/lib/autonomous-remediation/lkg/ai-gateway.config.yaml`.
3. LKG file passes static syntax verification and YAML structural schema validation.
4. Advisory lock `/var/run/remediation/ai-gateway.lock` acquired.

#### Remediation Actions (Sequential)
1. **Journal Invalidation Event**: Record corrupted file SHA-256 hash, byte size, and git/change provenance into transaction journal.
2. **Quarantine Corrupted Config**:
   - Move `/etc/ai-gateway/config.yaml` to `/var/lib/autonomous-remediation/quarantine/config-[timestamp].yaml.corrupt`.
3. **Atomic LKG Restoration**:
   - Copy `/var/lib/autonomous-remediation/lkg/ai-gateway.config.yaml` to `/etc/ai-gateway/config.yaml.lkg`.
   - Atomically rename to `/etc/ai-gateway/config.yaml`.
   - Flush filesystem metadata via `syncfs(2)`.
4. **Trigger Service Spawn/Reload**:
   - Issue `SIGTERM` followed by supervised restart or issue `SIGHUP` if daemon supports dynamic config re-read.

#### Postconditions (Ground-Truth Invariants)
1. SHA-256 of deployed configuration matches LKG exactly:
   $$\text{SHA256}(\text{ActiveConfig}) \equiv \text{SHA256}(\text{LKGConfig})$$
2. Target daemon process running (`/proc/[pid]/status` state `R` or `S`).
3. Ground-truth HTTP health probe returns `200 OK` within $3.0\,\text{s}$.
4. Prometheus metrics confirm active config hash matches LKG.

#### Rollback Sequence
- If restoring LKG also fails to start the daemon (e.g. underlying OS environment or kernel port conflict):
  1. Abort further automated actions.
  2. Lock target circuit breaker (`remediation_circuit_breaker_state = 2`).
  3. Emit Sev-1 PagerDuty alert: `LKG_CONFIGURATION_RESTORE_FAILED_HOST_QUARANTINE_REQUIRED`.

---

## 4. Local Chaos Injection & Verification Test Procedures

To rigorously validate the remediation engine, the following test scripts simulate each production failure mode locally and verify automated recovery and rollback behavior.

### 4.1. Chaos Test 1: Disk Saturation Simulation & Auto-Drain Test

```bash
#!/usr/bin/env bash
# file: /root/autonomous-remediation-engine/tests/chaos/chaos_disk_saturation.sh
set -euo pipefail

echo "===> [TEST 1] Initiating Disk Saturation Chaos Test..."
TARGET_DIR="/var/log/ai-gateway"
mkdir -p "${TARGET_DIR}"

# 1. Create 5 dummy rotated log archives with old timestamps (older than 48 hours)
echo "Generating synthetic expired log archives..."
for i in {1..5}; do
    FILE="${TARGET_DIR}/ai-gateway.log.2026-09-1${i}.gz"
    fallocate -l 200M "${FILE}"
    # Set modification time to 3 days ago
    touch -d "3 days ago" "${FILE}"
done

echo "Current logs in ${TARGET_DIR}:"
ls -lh "${TARGET_DIR}"

# 2. Trigger the autonomous remediation disk drain runbook directly via CLI
echo "Invoking autonomous remediation engine disk drain..."
/usr/local/bin/autonomous-remediation-ctl run --runbook=disk_log_drain --target=ai-gateway

# 3. Assert Postconditions
echo "Verifying postconditions..."
REMAINING_FILES=$(ls "${TARGET_DIR}"/*.gz 2>/dev/null | wc -l)
if [ "${REMAINING_FILES}" -eq 0 ]; then
    echo "SUCCESS: Expired logs safely drained. Invariants preserved."
else
    echo "ERROR: Expected 0 expired archives, found ${REMAINING_FILES}" >&2
    exit 1
fi
```

### 4.2. Chaos Test 2: Process Deadlock Simulation & Escalation Test

```bash
#!/usr/bin/env bash
# file: /root/autonomous-remediation-engine/tests/chaos/chaos_process_deadlock.sh
set -euo pipefail

echo "===> [TEST 2] Initiating Process Deadlock Chaos Test..."

# 1. Spawn a mock target process simulating ai-gateway
python3 -c "
import signal, time, sys
def handler(signum, frame):
    sys.stderr.write('Ignoring SIGTERM to simulate deadlock\n')
signal.signal(signal.SIGTERM, handler)
sys.stderr.write('Mock ai-gateway running...\n')
while True:
    time.sleep(1)
" &
MOCK_PID=$!
echo "${MOCK_PID}" > /var/run/ai-gateway.pid
echo "Mock deadlocked ai-gateway started with PID ${MOCK_PID}"

# 2. Trigger deadlock restart runbook
echo "Triggering service_deadlock_restart runbook..."
/usr/local/bin/autonomous-remediation-ctl run --runbook=service_deadlock_restart --target=ai-gateway

# 3. Verify that SIGTERM escalation to SIGKILL terminated the deadlocked process
if kill -0 "${MOCK_PID}" 2>/dev/null; then
    echo "ERROR: Process ${MOCK_PID} still alive! Deadlock escalation failed." >&2
    kill -9 "${MOCK_PID}" 2>/dev/null || true
    exit 1
else
    echo "SUCCESS: Deadlocked process successfully terminated via SIGKILL escalation ladder."
fi
```

### 4.3. Chaos Test 3: TLS Expiration Simulation & Hot-Reload Test

```bash
#!/usr/bin/env bash
# file: /root/autonomous-remediation-engine/tests/chaos/chaos_tls_expiry.sh
set -euo pipefail

echo "===> [TEST 3] Initiating TLS Expiry and Zero-Downtime Reload Chaos Test..."
STAGING_DIR="/var/lib/autonomous-remediation/staging"
CERT_DIR="/etc/ssl/certs"
KEY_DIR="/etc/ssl/private"
mkdir -p "${STAGING_DIR}" "${CERT_DIR}" "${KEY_DIR}"

# 1. Generate an expiring certificate (valid for 2 days)
openssl req -x509 -nodes -days 2 -newkey rsa:2048 \
    -keyout "${KEY_DIR}/ai-gateway.key" \
    -out "${CERT_DIR}/ai-gateway.crt" \
    -subj "/CN=127.0.0.1" 2>/dev/null

# 2. Generate a valid renewed certificate in staging (valid for 365 days)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${STAGING_DIR}/tls.key" \
    -out "${STAGING_DIR}/tls.crt" \
    -subj "/CN=127.0.0.1" 2>/dev/null

NEW_SERIAL=$(openssl x509 -in "${STAGING_DIR}/tls.crt" -noout -serial | cut -d= -f2)

# 3. Trigger TLS renewal runbook
echo "Invoking TLS reload runbook..."
/usr/local/bin/autonomous-remediation-ctl run --runbook=tls_cert_reload --target=ai-gateway

# 4. Assert deployed certificate serial matches new serial
ACTIVE_SERIAL=$(openssl x509 -in "${CERT_DIR}/ai-gateway.crt" -noout -serial | cut -d= -f2)
if [ "${ACTIVE_SERIAL}" == "${NEW_SERIAL}" ]; then
    echo "SUCCESS: Active certificate atomically upgraded to serial ${ACTIVE_SERIAL}."
else
    echo "ERROR: Serial mismatch! Expected ${NEW_SERIAL}, got ${ACTIVE_SERIAL}" >&2
    exit 1
fi
```

### 4.4. Chaos Test 4: Corrupted Configuration & Automated Rollback Test

```bash
#!/usr/bin/env bash
# file: /root/autonomous-remediation-engine/tests/chaos/chaos_config_rollback.sh
set -euo pipefail

echo "===> [TEST 4] Initiating Corrupted Configuration Rollback Chaos Test..."
CONFIG_DIR="/etc/ai-gateway"
LKG_DIR="/var/lib/autonomous-remediation/lkg"
mkdir -p "${CONFIG_DIR}" "${LKG_DIR}"

# 1. Establish verified Last-Known-Good configuration
cat << 'EOF' > "${LKG_DIR}/ai-gateway.config.yaml"
server:
  host: 127.0.0.1
  port: 8080
  timeout_seconds: 30
EOF

cp "${LKG_DIR}/ai-gateway.config.yaml" "${CONFIG_DIR}/config.yaml"
LKG_HASH=$(sha256sum "${LKG_DIR}/ai-gateway.config.yaml" | awk '{print $1}')

# 2. Inject adversarial corrupt configuration (syntax error)
cat << 'EOF' > "${CONFIG_DIR}/config.yaml"
server:
  host: 127.0.0.1
  port: INVALID_PORT_STRING_TRIGGERING_PARSER_ERROR: [unterminated
EOF

echo "Corrupted configuration injected into ${CONFIG_DIR}/config.yaml"

# 3. Trigger configuration rollback runbook
echo "Invoking configuration rollback runbook..."
/usr/local/bin/autonomous-remediation-ctl run --runbook=config_rollback --target=ai-gateway

# 4. Assert active configuration was safely reverted to LKG
ACTIVE_HASH=$(sha256sum "${CONFIG_DIR}/config.yaml" | awk '{print $1}')
if [ "${ACTIVE_HASH}" == "${LKG_HASH}" ]; then
    echo "SUCCESS: Corrupted config safely rolled back to LKG hash ${LKG_HASH}."
else
    echo "ERROR: Rollback failed! Current hash ${ACTIVE_HASH} does not match LKG ${LKG_HASH}" >&2
    exit 1
fi
```

---

## 5. Day-2 Operations & CLI Control Interface

The `autonomous-remediation-ctl` administrative tool allows operators to inspect and manage the engine:

### 5.1. Target Status & Lock Inspection
```bash
# Query active lock state and circuit breaker penalty for all targets
autonomous-remediation-ctl status

# Output:
# TARGET              LOCK       CIRCUIT    PENALTY  LAST_ACTION           OUTCOME
# ai-gateway          UNLOCKED   CLOSED     0        2026-09-22 18:20:00   SUCCESS
# guardrail-proxy     UNLOCKED   CLOSED     0        2026-09-22 17:45:12   SUCCESS
```

### 5.2. Manual Circuit Breaker Reset
When a target circuit breaker has entered the **LOCKED** state due to flap damping:
```bash
# Unlock circuit breaker following manual incident resolution
autonomous-remediation-ctl circuit reset --target=ai-gateway --reason="Incident #4928 resolved root database deadlock"
```

### 5.3. Dry-Run Execution Mode
Operators can test runbook execution in dry-run mode, which verifies preconditions and logs planned mutations without modifying the host filesystem or signaling processes:
```bash
autonomous-remediation-ctl run --runbook=disk_log_drain --target=ai-gateway --dry-run
```

### 5.4. Cryptographic Audit Chain Verification
Verify the tamper-evident integrity of the SHA-256 HMAC audit ledger from genesis to tail:
```bash
autonomous-remediation-ctl audit verify

# Output:
# Verified 1,482 cryptographic audit records.
# Head Hash: 8f9b2d3e4a... [VALID]
# Tamper status: ZERO_TAMPERING_DETECTED
```
