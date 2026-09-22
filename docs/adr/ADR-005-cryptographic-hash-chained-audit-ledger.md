# ADR-005: Cryptographic Hash-Chained Audit Ledger

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

The Autonomous Remediation Engine (`autonomous-remediation-engine`) executes high-privilege system mutations against production hosts - including signaling processes, truncating and rotating files, rolling back configurations, and swapping TLS certificates. 

Under [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md), our systems must accumulate *evidence of real engineering work* and preserve non-repudiation:
- If a service experiences an outage, operators must prove whether the failure was caused by human error, an external dependency failure, or an autonomous remediation action.
- If a host is compromised, an adversary who gains root access must not be able to retroactively alter, reorder, or delete remediation audit records without cryptographic detection.
- Audit logging must never depend on external network connectivity or cloud daemons, guaranteeing that audit durability is preserved even during total network blackouts.

We must define the architecture of the persistence mechanism used to record all autonomous remediation events.

---

## 2. Decision Drivers

1. **Tamper-Evident Non-Repudiation**: Any retroactive tampering, record omission, reordering, or truncation must be mathematically provable and trigger an immediate integrity alarm.
2. **Zero External Daemon Dependencies**: The audit trail must be recorded directly to local POSIX disk without requiring external logging daemons, databases, or cloud APIs.
3. **Crash Durability & Atomicity**: The ledger must survive sudden host power loss, kernel panics, and process crashes without corrupted record chains or uncommitted torn writes.
4. **Minimal Write Latency**: Dispatched events must be serialized and flushed via `fsync(2)` in $< 10\,\text{ms}$ to satisfy MTTR requirements.
5. **Simplicity and Auditability**: Pure standard library Go implementation using NIST-approved cryptographic primitives (`crypto/sha256`, `crypto/hmac`).

---

## 3. Considered Options

1. **Append-Only HMAC-SHA256 Hash-Chained Write-Ahead Log (Selected)**: Structured binary/JSON-Lines records bound in a cryptographic hash chain using host-bound HMAC-SHA256 digests, sector-aligned and flushed via `fsync(2)`.
2. **Standard Local Syslog / Flat File (`/var/log/remediation.log`)**: Writing plaintext structured JSON logs via standard logging libraries.
3. **External Centralized Immutable Ledger (AWS QLDB / Kafka / CloudTrail)**: Streaming audit events across the network to a managed cloud database.

---

## 4. Deep Technical Comparison

### 4.1. Comparison Matrix

| Evaluation Dimension | HMAC-SHA256 Hash-Chained WAL (Selected) | Flat File / Syslog | External Cloud Ledger (QLDB / CloudTrail) |
| :--- | :--- | :--- | :--- |
| **Tamper Evidence** | **Cryptographic Merkle Proof (HMAC-SHA256)** | None (Root user can rewrite lines) | Cryptographic signature via cloud KMS |
| **Truncation & Deletion Detection** | **Provable via broken chain pointer** | Undetectable | Detectable via cloud sequencing |
| **External Network Dependency** | **Zero (Local filesystem storage)** | Zero | High (Requires active cloud network) |
| **Partition Resilience** | **100% Operational during network isolation** | 100% Operational | Fails when network is partitioned |
| **Write Latency Overhead** | **Sub-millisecond (< 5ms with fsync)** | < 1ms (unbuffered) | 50ms - 250ms (network round-trip) |
| **Crash Recovery & Torn Writes** | **Sector-aligned records + block checksums** | Prone to torn JSON lines | Handled by cloud provider |

---

### 4.2. Detailed Evaluation of Rejected Alternatives

#### Alternative 2: Flat File / Syslog
*Why it was rejected*:
Flat log files offer zero cryptographic protection. If a malicious actor or errant script modifies a configuration file and covers their tracks by running `sed -i` on `/var/log/remediation.log` or truncating the file with `> /var/log/remediation.log`, the modification is completely undetectable. Flat logs do not provide legal non-repudiation or tamper evidence.

#### Alternative 3: External Centralized Ledger (AWS QLDB / Kafka / CloudTrail)
*Why it was rejected*:
1. **Network Partition Vulnerability**: Remediation often takes place during severe network degradation. If the host network interface drops or DNS fails, the engine would be blocked from logging to the cloud. Under a fail-secure posture, this would halt all remediations precisely when the host needs autonomous recovery.
2. **Cloud Dependency Invariant Violation**: Violates [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md) and [08-autonomous-remediation-engine.md](file:///root/company-project-specs/08-autonomous-remediation-engine.md) by introducing external vendor lock-in and multi-layer failure points.

---

## 5. Decision Outcome

We select an **Append-Only HMAC-SHA256 Hash-Chained Write-Ahead Log (WAL)** stored locally at `/var/lib/autonomous-remediation/audit/audit.wal`.

### 5.1. Cryptographic Hash-Chain Mathematics
Every audit event $E_i$ is cryptographically chained to its predecessor $E_{i-1}$.

Let:
- $H_0 = \text{GenesisHash} = \text{SHA256}(\text{"AUTONOMOUS_REMEDIATION_GENESIS_2026"}) \in \{0,1\}^{256}$
- $K_{\text{audit}}$ be a 256-bit symmetric secret key stored at `/etc/autonomous-remediation/certs/audit.key` (permission 0400, root only).
- $R_i$ be the canonical serialized byte representation of the $i$-th audit record:
  $$R_i = \text{Sequence}_i \parallel \text{Timestamp}_i \parallel \text{TargetID} \parallel \text{Action} \parallel \text{PreconditionsMet} \parallel \text{PostconditionsMet} \parallel \text{Outcome} \parallel \text{RollbackTxID}$$

The cryptographic hash $H_i$ of the $i$-th record is computed as:

$$H_i = \text{HMAC-SHA256}\Big(K_{\text{audit}}, \; H_{i-1} \parallel R_i\Big)$$

```
+---------------------------------------------------------------------------------------------------------+
| Record i-1                                                                                              |
| Seq: 141 | Target: ai-gateway | Action: drain | Hash(i-1): 7e8b2a1c...                                  |
+----------------------------------------------------+----------------------------------------------------+
                                                     |
                                                     v (Chained into HMAC)
+----------------------------------------------------+----------------------------------------------------+
| Record i                                                                                                |
| Seq: 142 | PrevHash: 7e8b2a1c... | Target: ai-gateway | Action: restart | Hash(i): 3f99d4e1...           |
| Payload: {"pid": 29814, "pre": true, "post": true, "outcome": "SUCCESS", "txid": "20260922-tx-00142"}  |
+----------------------------------------------------+----------------------------------------------------+
                                                     |
                                                     v (Chained into HMAC)
+----------------------------------------------------+----------------------------------------------------+
| Record i+1                                                                                              |
| Seq: 143 | PrevHash: 3f99d4e1... | Target: guardrail-proxy | Action: tls_reload | Hash(i+1): 9a11f0bb... |
+---------------------------------------------------------------------------------------------------------+
```

### 5.2. Tamper-Evidence Guarantees
1. **Modification Detection**: If an attacker alters any byte in Record $i$ (e.g. changing `outcome: ROLLED_BACK` to `outcome: SUCCESS`), the calculated digest $\text{HMAC}(K, H_{i-1} \parallel R_i')$ will not match $H_i$.
2. **Deletion & Truncation Detection**: If an attacker removes Record $i$, Record $i+1$'s `PrevHash` will point to $H_i$ which no longer exists, breaking the chain.
3. **Insertion & Reordering Detection**: Inserting a forged record between $i$ and $i+1$ invalidates the chain from that point forward because the adversary lacks $K_{\text{audit}}$ to generate valid HMACs.

### 5.3. Sector Alignment and Crash Resilience
To guarantee crash consistency without torn writes:
1. Each journal entry is formatted into a fixed sector boundary ($4096\,\text{bytes}$ aligned) with a 32-bit CRC32 checksum in the record header.
2. Writes are committed using Go standard library file descriptor synchronization:
   ```go
   // Synchronously commit audit record to non-volatile disk
   if _, err := auditFile.Write(recordBytes); err != nil {
       return fmt.Errorf("audit write failed: %w", err)
   }
   if err := auditFile.Sync(); err != nil {
       return fmt.Errorf("audit fsync failed: %w", err)
   }
   ```
3. If the host experiences power loss during a write, the subsequent boot recovery routine detects the torn block via CRC32 mismatch, truncates the uncommitted partial block, and verifies that the preceding hash chain is intact.

### Consequences
1. **Cryptographic Proof of Compliance**: Provides complete, indisputable causal evidence for every automated mutation.
2. **Complete Autonomy**: Zero reliance on external network connectivity or cloud services.
3. **High Durability**: Sector-aligned `fsync` guarantees zero data loss on unexpected power cuts.
