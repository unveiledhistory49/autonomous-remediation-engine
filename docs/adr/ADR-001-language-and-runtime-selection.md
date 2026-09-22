# ADR-001: Language and Runtime Selection for Autonomous Remediation Engine

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

The Autonomous Remediation Engine (`autonomous-remediation-engine`) operates as an autonomous, host-local system supervisor on Linux ARM64 platforms. It is responsible for autonomously remediating infrastructure faults, process deadlocks, disk capacity saturation, and configuration corruptions across platform workloads such as [ai-gateway](file:///root/company-project-specs/01-ai-gateway.md) and [ai-security-guardrail-proxy](file:///root/company-project-specs/09-ai-security-guardrail-proxy.md).

Operating as a privileged system supervisor introduces strict engineering constraints:
1. **Low Latency & High Predictability**: Mean Time to Detect (MTTD) must remain strictly under $1.0\,\text{s}$ (p99) and Mean Time to Remediate (MTTR) under $5.0\,\text{s}$ (p95), bound in [SLO.md](file:///root/autonomous-remediation-engine/docs/SLO.md).
2. **Zero External Runtime Dependencies**: The daemon must operate autonomously without external database daemons (no PostgreSQL, Redis, etcd), container runtimes (no Docker daemon dependency), or third-party cloud SaaS dependencies.
3. **Direct OS & Kernel Integration**: The engine requires direct interaction with Linux system calls: `pidfd_open(2)`, `pidfd_send_signal(2)`, `flock(2)`, `fcntl(2)`, `renameat2(2)`, and `/proc` pseudo-filesystem inspection.
4. **Static Single-Binary Portability on Linux ARM64**: The executable must compile into a fully static binary (`CGO_ENABLED=0`) capable of running on bare-metal ARM64 servers, virtual machines, and unprivileged systemd execution targets.
5. **Robust Concurrency & Safe I/O Multiplexing**: Concurrent handling of incoming alert streams, non-blocking lock coordination, background health probes, and file journaling without deadlocks or thread pool starvation.

We must choose the primary implementation language and runtime environment for the daemon.

---

## 2. Decision Drivers

1. **Self-Contained Deployment**: Capable of single-binary static compilation with zero runtime package requirements on Linux ARM64.
2. **Standard Library Completeness**: Out-of-the-box support for networking (`net/http`, Unix domain sockets), cryptographic operations (`crypto/sha256`, `crypto/hmac`), OS primitives (`syscall`, `os`, `os/signal`, `os/exec`), and concurrency (`sync`, `sync/atomic`).
3. **Memory Safety and Predictable Lifecycle**: Immunity to memory corruption bugs (buffer overflows, use-after-free) without requiring complex manual memory tracking across asynchronous stage pipelines.
4. **Minimal Runtime Footprint**: Resident memory consumption $< 50\,\text{MB}$ under idle and active load to prevent triggering the host kernel OOM killer during host memory pressure incidents.
5. **Code Maintainability & Auditability**: Comply with [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md) by selecting boring, proven, reliable infrastructure that avoids speculative abstractions.

---

## 3. Considered Options

We evaluated three candidate runtime environments:

1. **Go 1.23+ with Pure Standard Library (Selected)**: Statically compiled, garbage-collected language with lightweight M:N green threads (goroutines) and extensive standard library system call interfaces.
2. **Rust (`tokio` + `libc` / `nix`)**: Systems programming language offering zero-cost abstractions, deterministic destruction without garbage collection, and strict compile-time borrow checking.
3. **Python 3.12 (`asyncio` + `systemd-python`)**: Dynamic interpreted language commonly utilized for administrative tooling and scripting.

---

## 4. Deep Technical Comparison

### 4.1. Comparison Matrix

| Evaluation Dimension | Go 1.23+ (Selected) | Rust (`tokio` + `nix`) | Python 3.12 (`asyncio`) |
| :--- | :--- | :--- | :--- |
| **Target Architecture** | Native Linux ARM64 (`aarch64`) | Native Linux ARM64 (`aarch64`) | Requires host Python interpreter & libs |
| **Binary Linkage** | 100% Static ELF (`CGO_ENABLED=0`) | Static via `x86_64-unknown-linux-musl` | Interpreted (requires dynamic `libc`, `.so`) |
| **External Package Dependencies** | **Zero (Pure Standard Library)** | High (requires dozens of external crates) | Extreme (virtualenvs, pip packages) |
| **Linux Syscall Access (`pidfd`, `flock`)**| Native `syscall` and `golang.org/x/sys/unix` | Via `libc` or `nix` crates | Requires ctypes or native C extensions |
| **Memory Footprint (Idle / Active)** | **~18 MB / ~32 MB** | **~6 MB / ~12 MB** | ~65 MB / ~180 MB |
| **Garbage Collection Overhead** | Concurrent tri-color (< 200µs pause) | **Zero (Deterministic compile-time)** | GIL stalls + Stop-the-world GC (10-100ms) |
| **Concurrency Model** | M:N Goroutines + channels | Async state machines + cooperative tasks | Single-threaded cooperative event loop |
| **Crash Resilience & Panics** | Recoverable panics per goroutine | Catchable unwinds (`panic::catch_unwind`) | Unhandled exceptions terminate event loop |
| **Long-Term Auditability** | High (small language, readable stdlib) | Medium (complex trait/lifetime hierarchy) | Low (duck-typed, fragile runtime errors) |

---

### 4.2. Detailed Evaluation of Rejected Alternatives

#### Alternative 1: Rust (`tokio` + `nix`)
*Why it was considered*:
Rust provides exceptional performance, minimal memory footprints (~8MB), and deterministic memory deallocation without a garbage collector. For critical infrastructure software, Rust eliminates data races and memory bugs at compile time.

*Why it was rejected*:
1. **Dependency Proliferation**: While a basic Rust binary can be statically compiled, implementing the required feature set (HTTP server/client, JSON parsing, Unix domain sockets, process signaling, HMAC crypto, and file locking) requires importing 40+ external third-party crates (`tokio`, `hyper`, `serde`, `nix`, `ring`, etc.). This violates our core invariant: *Zero external runtime or third-party dependencies*.
2. **Cognitive Overhead in Stateful Transaction Rollbacks**: The engine maintains a stateful two-phase transaction journal that interacts with mutating operating system handles. In Rust, managing shared mutable state across asynchronous event loops and crash recovery paths requires complex `Arc<RwLock<T>>` abstractions and manual lifetime plumbing, increasing the risk of subtle deadlocks and hindering operational readability.
3. **Marginal Benefit Over Modern Go**: Go 1.23+ GC pauses are bounded under $200\,\mu\text{s}$, which is two orders of magnitude faster than our $1.0\,\text{s}$ MTTD and $5.0\,\text{s}$ MTTR thresholds. Rust's microsecond-level advantage provides zero practical benefit in remediation workflows where process restarts and filesystem `sync` calls take hundreds of milliseconds.

#### Alternative 2: Python 3.12 (`asyncio`)
*Why it was considered*:
Python is ubiquitous for SRE automation scripts, offering rapid prototyping and familiar syntax for operational teams.

*Why it was rejected*:
1. **Non-Autonomous Runtime Dependency**: Python cannot produce a self-contained static binary. It requires an installed operating system interpreter, shared C libraries (`glibc`, `libssl`), and site-packages. If the host filesystem or package manager is corrupted, Python fails to execute - rendering it useless precisely when an emergency remediation supervisor is needed.
2. **Global Interpreter Lock (GIL) and Process Blocking**: Remediation operations frequently involve synchronous blocking calls: reading `/proc` files, acquiring kernel locks, or waiting on `fsync(2)`. In Python, a single thread stalled on a disk flush or blocking syscall freezes the entire `asyncio` event loop.
3. **Lack of Compile-Time Guarantees**: Python's dynamic typing introduces runtime `AttributeError` or `KeyError` risks that can manifest during rare disaster recovery sequences.

---

## 5. Decision Outcome

We select **Go 1.23+ with pure standard library implementation and zero external dependencies** (`CGO_ENABLED=0`) as the foundational runtime for the Autonomous Remediation Engine.

### Positive Consequences
1. **True Autonomous Single-Binary Artifact**: The daemon compiles into a single static ELF binary with zero dynamic library linkages. It runs directly on Linux ARM64 without requiring packages, daemons, or container engines.
2. **Complete Self-Contained Standard Library**: Every required capability - HTTP client/server for telemetry and health checks, JSON parsing, SHA-256 HMAC cryptographic primitives, Unix domain sockets, signal trapping, and low-level syscalls - is satisfied entirely by the Go 1.23+ standard library (`net/http`, `crypto/hmac`, `crypto/sha256`, `os`, `syscall`, `sync`).
3. **Predictable Sub-Millisecond Concurrency**: Lightweight goroutines allow concurrent alert ingestion, background health polling, and supervised action dispatching with negligible memory overhead (~2KB stack per goroutine) and sub-millisecond GC pauses.
4. **Crash Containment**: Each remediation execution runs in an isolated goroutine wrapped with `recover()`. A panic during runbook execution is intercepted, logged to the transaction journal, and triggers an automated rollback without crashing the parent supervisory daemon.

### Negative Consequences & Mitigations
1. **Manual System Call Marshaling**: Standard Go `syscall` does not expose newer Linux system calls like `pidfd_open` directly.
   - *Mitigation*: Invoke system calls directly using `syscall.Syscall(SYS_PIDFD_OPEN, uintptr(pid), 0, 0)` with hardcoded Linux ARM64 syscall numbers (SYS_PIDFD_OPEN = 434, SYS_PIDFD_SEND_SIGNAL = 424).
2. **Garbage Collection Presence**: While bounded, Go does utilize a GC.
   - *Mitigation*: Maintain zero heap allocations on hot monitoring paths using `sync.Pool` for byte buffers and pre-allocated telemetry structures.
