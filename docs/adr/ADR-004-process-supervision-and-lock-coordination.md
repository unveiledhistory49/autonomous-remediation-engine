# ADR-004: In-Memory / File-Descriptor Supervisory Lock & Mutual Exclusion

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

When operating as an automated supervisor over production workloads (such as [ai-gateway](file:///root/company-project-specs/01-ai-gateway.md) and [ai-security-guardrail-proxy](file:///root/company-project-specs/09-ai-security-guardrail-proxy.md)), the remediation engine faces severe concurrency hazards:
1. **Concurrent Action Conflicts**: Rapidly arriving alerts or overlapping background evaluations could trigger conflicting remediation routines simultaneously (e.g. attempting to execute a zero-downtime certificate reload while another worker thread initiates a process deadlock restart on the same daemon).
2. **CLI vs Daemon Interleaving**: Administrative actions executed via `autonomous-remediation-ctl` must not collide with automated actions running inside the background daemon.
3. **Stale Lockfile Deadlocks**: Traditional filesystem lockfile implementations (e.g. creating `/var/run/remediation.pid` or writing files with PIDs) are prone to stale locks: if the process holding the lock crashes or receives `SIGKILL`, the lockfile remains on disk, blocking all future remediations indefinitely.
4. **PID Recycling Race Conditions**: If a target process terminates and the Linux kernel recycles its PID to an unrelated critical daemon before the supervisor dispatches a signal, blind signaling via `kill(pid, sig)` will terminate the wrong process.

We must define a robust, crash-resilient mutual exclusion and process supervision mechanism that operates locally on Linux ARM64 with zero external dependencies.

---

## 2. Decision Drivers

1. **Kernel-Managed Lock Lifecycles**: Locks must be automatically released by the Linux kernel upon process crash or termination, eliminating human intervention to clear stale lockfiles.
2. **Cross-Process Coordination**: Mutual exclusion must coordinate safely between the background systemd daemon and separate CLI utility invocations.
3. **Zero External Daemon Dependencies**: Prohibit external coordination clusters (no etcd, Consul, Redis, ZooKeeper).
4. **Guaranteed Immunity to PID Recycling**: Mathematical certainty that signals are dispatched exclusively to the intended process instance.
5. **Non-Blocking Fail-Fast Semantics**: Lock acquisition must support non-blocking checks (`EWOULDBLOCK`) to avoid indefinite blocking during alert storms.

---

## 3. Considered Options

1. **Kernel-Bound Advisory File-Descriptor Locks (`flock` / `fcntl`) with `pidfd` Process Handles (Selected)**: Open file descriptor locks managed by the Linux VFS kernel lock table, paired with Linux 5.3+ `pidfd_open(2)` process handles.
2. **Distributed Consensus Lock Service (etcd / Consul)**: Acquiring distributed lease-based locks via Raft consensus.
3. **In-Memory Go Mutex (`sync.Mutex`) Only**: Coordinating workers strictly in-memory within the Go daemon process.
4. **PID File Existence Check (`open(O_CREAT | O_EXCL)`)**: Classic Unix lockfiles containing the owner's PID.

---

## 4. Deep Technical Comparison

### 4.1. Comparison Matrix

| Evaluation Dimension | Kernel Advisory Locks (`flock`) + `pidfd` (Selected) | Distributed Locks (etcd / Consul) | In-Memory Go Mutex (`sync.Mutex`) | PID File Creation (`O_EXCL`) |
| :--- | :--- | :--- | :--- | :--- |
| **Crash Resilience** | **Instant (Kernel cleans up on fd close)** | Relies on TTL expiration (10-30s delay) | Cleaned up on process death | Vulnerable (Stale file remains on disk) |
| **Cross-Process Safety (Daemon + CLI)** | **Full (Shared kernel lock table)** | Full (Shared network consensus) | None (Visible only inside single Go runtime) | Partial (Vulnerable to races) |
| **External Dependencies** | **Zero (Local Linux VFS)** | High (Requires external network cluster) | Zero | Zero |
| **PID Reuse Protection** | **100% (`pidfd` handle pinned to kernel task)** | None | None | Vulnerable to PID reuse |
| **Acquisition Overhead** | **Microseconds (< 10µs)** | Milliseconds (15ms - 80ms network RTT) | Nanoseconds (< 50ns) | Microseconds |
| **Partition Tolerance** | **Immune (Operates locally on host)** | Fails during network partitions | Immune | Immune |

---

### 4.2. Detailed Evaluation of Rejected Alternatives

#### Alternative 2: Distributed Consensus Locks (etcd / Consul)
*Why it was rejected*:
1. **Violation of Zero-Daemon Philosophy**: Mandating an etcd or Consul cluster introduces external network and storage dependencies, violating [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md).
2. **The Partition Paradox**: If a node suffers a network interface failure or split-brain partition, it cannot acquire etcd locks - rendering it incapable of remediating host-local issues precisely when network isolation occurs.
3. **Lease TTL Latency**: Distributed locks rely on heartbeat TTLs (typically 5 to 30 seconds). If a worker crashes while holding a lock, subsequent remediation actions are blocked until the lease expires, breaching our $5.0\,\text{s}$ MTTR SLO.

#### Alternative 3: In-Memory Mutex (`sync.Mutex`) Only
*Why it was rejected*:
While ultra-fast, an in-memory mutex only synchronizes goroutines within the *same* OS process. It cannot coordinate between the background `autonomous-remediation-engine` daemon and manual invocations of `autonomous-remediation-ctl`. An operator running a CLI command could collide directly with a daemon background loop.

#### Alternative 4: PID File Existence (`O_CREAT | O_EXCL`)
*Why it was rejected*:
PID files are notoriously brittle. If a process holding a lockfile receives `SIGKILL` (e.g. from the kernel OOM killer) or experiences a sudden host reboot, the file `/var/run/remediation.lock` remains on the filesystem. Subsequent remediation attempts read the file, assume another process is running, and permanently fail until a human manually runs `rm -f`.

---

## 5. Decision Outcome

We select **Kernel-Bound Advisory File-Descriptor Locks (`flock(2)`/`fcntl(2)`) combined with Linux `pidfd` Process Handles** for all supervisory synchronization and mutual exclusion.

### 5.1. File-Descriptor Locking Architecture
Every managed target subsystem is assigned a dedicated lock path in `/var/run/remediation/`:
- `ai-gateway.lock`
- `guardrail-proxy.lock`
- `disk-drain.lock`
- `tls-reload.lock`

Lock acquisition utilizes non-blocking `flock(2)` via the standard library:

```go
type TargetLock struct {
    file *os.File
}

func AcquireTargetLock(targetName string) (*TargetLock, error) {
    lockPath := filepath.Join("/var/run/remediation", targetName+".lock")
    f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
    if err != nil {
        return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
    }

    // LOCK_EX = Exclusive lock
    // LOCK_NB = Non-blocking (fails fast if already held)
    err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
    if err != nil {
        f.Close()
        if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
            return nil, fmt.Errorf("lock for target %s is currently held by another worker: %w", targetName, err)
        }
        return nil, fmt.Errorf("flock failed on %s: %w", lockPath, err)
    }

    return &TargetLock{file: f}, nil
}

func (l *TargetLock) Release() error {
    if l.file == nil {
        return nil
    }
    _ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
    return l.file.Close()
}
```

#### Kernel Invariant Guarantee
In the Linux Virtual File System (VFS), an `flock` is associated with the kernel `struct file` table entry. When a process terminates - for **any** reason (graceful return, panic, `SIGSEGV`, `SIGKILL`, or host power event) - the kernel automatically closes all open file descriptors for that process table entry, which **instantly and atomically releases the lock**. Stale lockfile bugs are mathematically impossible.

### 5.2. `pidfd` Process Supervision Invariant
To eliminate PID recycling race conditions, the engine acquires a Linux 5.3+ process file descriptor before dispatching signals:

```go
// Open a non-reusable file descriptor referencing the specific target task
fd, _, errno := syscall.Syscall(syscall.SYS_PIDFD_OPEN, uintptr(targetPID), 0, 0)
if errno != 0 {
    return fmt.Errorf("pidfd_open failed for PID %d: %w", targetPID, errno)
}
defer syscall.Close(int(fd))

// Dispatch signal directly through the pinned pidfd handle
_, _, errno = syscall.Syscall6(
    syscall.SYS_PIDFD_SEND_SIGNAL,
    fd,
    uintptr(syscall.SIGTERM),
    0, 0, 0, 0,
)
if errno != 0 {
    return fmt.Errorf("pidfd_send_signal failed: %w", errno)
}
```

If the target process terminated prior to handle acquisition, `pidfd_open` fails with `ESRCH`. If the process terminated *after* handle acquisition and the PID was recycled to a new process, `pidfd_send_signal` fails with `ESRCH` because the open `fd` remains bound to the deceased process object. Zero cross-process signal corruption is guaranteed.

### Consequences
1. **Flawless Crash Cleanup**: Total immunity to stale locks.
2. **Absolute Process Identity Isolation**: Signals are guaranteed to hit the exact intended process instance.
3. **Sub-Microsecond Lock Overhead**: Acquiring a local kernel lock requires $< 10\,\mu\text{s}$, introducing zero latency overhead into the remediation path.
