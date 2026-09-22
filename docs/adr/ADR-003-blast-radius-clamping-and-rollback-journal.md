# ADR-003: Blast-Radius Clamping & State Rollback Journal

- **Status**: Accepted
- **Deciders**: Core Systems Architecture & SRE Team
- **Date**: 2026-09-22
- **Context Files**:
  - [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md)
  - [08-autonomous-remediation-engine.md](file:///root/company-project-specs/08-autonomous-remediation-engine.md)
  - [FAILURE-MODES.md](file:///root/autonomous-remediation-engine/docs/FAILURE-MODES.md)
  - [SLO.md](file:///root/autonomous-remediation-engine/docs/SLO.md)
  - [OPERATIONS.md](file:///root/autonomous-remediation-engine/docs/OPERATIONS.md)

---

## 1. Context and Problem Statement

Privileged automation without bounded execution boundaries is an existential threat to production stability. If an automated remediation script suffers from a software defect, receives an unvetted parameter, or encounters an edge case, it can trigger catastrophic damage - such as wiping entire root filesystems, terminating unrelated system daemons, or saturating I/O buses with continuous disk writes.

Furthermore, distributed system operations frequently fail halfway through execution: a process restart script might terminate an active daemon but fail to bind the replacement port; a configuration update might overwrite a config file with invalid syntax before the parser validates it; or the host machine might experience a sudden kernel panic or power loss mid-transaction.

To satisfy the safety mandate in [08-autonomous-remediation-engine.md](file:///root/company-project-specs/08-autonomous-remediation-engine.md) and the $> 99.9\%$ Rollback Success Rate in [SLO.md](file:///root/autonomous-remediation-engine/docs/SLO.md), the system must guarantee that:
1. Every automated mutation is strictly clamped in its spatial and temporal impact.
2. Any partial or failed mutation can be atomically and idempotently reversed to a Last-Known-Good (LKG) state.

---

## 2. Decision Drivers

1. **Strict Blast-Radius Upper Bounds**: Hard, non-configurable limits on files touched, bytes modified, signals sent, and execution durations to prevent runaway automation loops.
2. **Crash-Resilient State Reversibility**: If the remediation daemon crashes or loses power midway through mutating a file or process, it must recover cleanly upon restart and restore the system to a known consistent state.
3. **Idempotent Compensating Actions**: Rolling back an action multiple times must always converge to the identical clean state without compounding errors.
4. **Zero External Storage Dependencies**: Rollback journals and snapshots must reside on the local POSIX filesystem without relying on cloud volume snapshots or external storage arrays.

---

## 3. Considered Options

1. **Two-Phase Write-Ahead Rollback Journal with Hard Invariant Clamps (Selected)**: Pre-allocating and staging compensating operations to an on-disk Write-Ahead Log (WAL) flushed via `fsync(2)` prior to mutation execution, combined with compile-time bounded resource caps.
2. **Filesystem Snapshotting (ZFS / Btrfs / LVM Snapshots)**: Triggering local CoW (Copy-on-Write) filesystem snapshots prior to every remediation action and rolling back subvolumes upon failure.
3. **Best-Effort Shell Script Trap Handlers (`trap 'cleanup' ERR EXIT`)**: Relying on ad-hoc shell script signal traps to revert changes upon command failures.

---

## 4. Deep Technical Comparison

### 4.1. Comparison Matrix

| Evaluation Dimension | Two-Phase WAL & Hard Clamps (Selected) | CoW Snapshots (ZFS/Btrfs/LVM) | Shell Traps (`trap ERR`) |
| :--- | :--- | :--- | :--- |
| **Crash Durability** | **Guaranteed (`fsync` WAL before mutation)** | High (CoW tree state intact) | Zero (Lost on SIGKILL or power cut) |
| **Portability & Host Requirements** | **100% POSIX (Standard ext4/xfs)** | Requires specific volume managers / filesystems | Standard bash |
| **Rollback Granularity** | Exact file, process, and socket level | Block / subvolume level (coarse) | Variable and unpredictable |
| **Blast Radius Enforcement** | **Rigid programmatic bounds ($N \le 10$, $B \le 50\text{GB}$)** | Coarse quota enforcement | None (prone to unconstrained `rm`) |
| **Execution Latency Overhead** | **Sub-millisecond disk write (< 5ms)** | 50ms - 500ms (snapshot sync) | 1ms |
| **Idempotency Proof** | Mathematical compensating function $f^{-1}(s)$ | Revert snapshot resets blocks | Custom, rarely idempotent |

---

### 4.2. Detailed Evaluation of Rejected Alternatives

#### Alternative 2: CoW Filesystem Snapshots (ZFS / Btrfs / LVM)
*Why it was considered*:
Volume-level copy-on-write snapshots provide complete system point-in-time recovery, allowing an entire disk subvolume to be rolled back instantly.

*Why it was rejected*:
1. **Host Environment Restrictions**: Production ARM64 edge nodes and cloud instances overwhelmingly deploy on standard `ext4` or `xfs` filesystems. Requiring `btrfs`, `zfs`, or pre-configured LVM thin pools violates our zero-host-dependency principle.
2. **Blast Radius of Volume Reversion**: Reverting a filesystem snapshot rolls back *all* writes on that volume, including unrelated telemetry logs, concurrent service requests, and operating system accounting data created during the remediation window.
3. **Lack of Process State Coordination**: A storage snapshot captures disk blocks, but has no mechanism to coordinate process signaling, PID tracking, or network socket state.

#### Alternative 3: Ad-Hoc Shell Script Traps
*Why it was considered*:
Bash scripts using `trap cleanup EXIT ERR` are the standard industry default for operational runbooks.

*Why it was rejected*:
1. **Zero Crash Resilience**: If the remediation process is terminated via `SIGKILL` (e.g. by the Linux Out-Of-Memory killer) or the host loses power, shell traps never fire. The system is left in a corrupted, half-modified state.
2. **Lack of Invariant Enforcement**: Shell scripts offer no type-safe enforcement of blast radius. A single typo (such as `rm -rf $DIR/` where `$DIR` is undefined) executes against the root directory.

---

## 5. Decision Outcome

We select a **Two-Phase Write-Ahead Rollback Journal with Hard Programmatic Blast-Radius Clamping**.

### 5.1. Blast-Radius Programmatic Clamp Architecture
Every runbook must pass through a strict compile-time and runtime clamp validator. The Go execution engine rejects any plan that violates the following bounds:

```go
type BlastRadiusClamp struct {
    MaxFilesModified    int           // Strictly <= 10 files
    MaxBytesDeleted     int64         // Strictly <= 50 GiB (53,687,091,200 bytes)
    MaxExecutionTime    time.Duration // Strictly <= 15.0 seconds
    MaxProcessesSignaled int          // Strictly == 1 target process
    AllowedPathPrefixes []string      // Strict whitelist
}

var ProductionClamp = BlastRadiusClamp{
    MaxFilesModified:    10,
    MaxBytesDeleted:     50 * 1024 * 1024 * 1024,
    MaxExecutionTime:    15 * time.Second,
    MaxProcessesSignaled: 1,
    AllowedPathPrefixes: []string{
        "/var/log/ai-gateway/",
        "/var/log/guardrail-proxy/",
        "/etc/ai-gateway/",
        "/etc/guardrail-proxy/",
        "/etc/ssl/certs/",
        "/etc/ssl/private/",
    },
}
```

If an action attempts to delete 11 files or modify `/etc/shadow`, the engine immediately halts with a `BLAST_RADIUS_VIOLATION` security tripwire.

### 5.2. Two-Phase Write-Ahead Rollback Protocol
State mutations execute under a strict two-phase commit protocol:

1. **Phase 1: Pre-Flight Journaling & Staging**:
   - The transaction generates a unique monotonic transaction ID (`txid`).
   - A dedicated journal file `/var/lib/autonomous-remediation/journal/[txid].wal` is opened.
   - For every targeted file, a full byte snapshot is copied to `/var/lib/autonomous-remediation/staging/[txid]/`.
   - The compensating reverse action $f^{-1}(s)$ is written to the WAL:
     ```json
     {
       "txid": "20260922-tx-00142",
       "action": "restore_file",
       "target": "/etc/ai-gateway/config.yaml",
       "staged_source": "/var/lib/autonomous-remediation/staging/20260922-tx-00142/config.yaml",
       "original_sha256": "8a3f...",
       "state": "PREPARED"
     }
     ```
   - The journal file descriptor is flushed synchronously via `syscall.Fsync(int(fd))`.

2. **Phase 2: Execution & Postcondition Gate**:
   - The mutation is executed against the host.
   - Ground-truth postconditions are evaluated.
   - If postconditions evaluate to `TRUE`: The transaction state is updated to `COMMITTED` in the WAL and flushed.
   - If postconditions evaluate to `FALSE` or a panic occurs: The engine enters the `ROLLING_BACK` state, executes the staged compensating actions in reverse order, asserts that the original state is restored, and records `ROLLED_BACK`.

### 5.3. Daemon Boot Recovery Routine
Upon daemon startup, the engine scans `/var/lib/autonomous-remediation/journal/`:
- Any journal file found in state `PREPARED` or `EXECUTING` indicates that the prior run crashed midway through mutation.
- The engine automatically replays the compensating rollback actions to revert the host to Last-Known-Good, logs the crash event, and marks the transaction `RECOVERED_ON_BOOT`.

### Consequences
1. **Mathematical Recovery Guarantee**: Every partial mutation is recoverable, directly satisfying the $> 99.9\%$ Rollback Success Rate SLO.
2. **Deterministic Safety Containment**: The system cannot perform unconstrained damage even if an errant runbook is triggered.
3. **Minimal Overhead**: The WAL requires $< 5\,\text{ms}$ of disk I/O, maintaining full compliance with sub-second MTTR objectives.
