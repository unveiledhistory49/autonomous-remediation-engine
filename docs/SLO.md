# Autonomous Remediation Engine Service Level Objectives (SLO) & Observability Specification

## 1. Context and Architectural Boundaries

This specification establishes the production Service Level Objectives (SLOs), Service Level Indicators (SLIs), error budget accounting models, and Prometheus metrics catalog for the Autonomous Remediation Engine (`autonomous-remediation-engine`).

Following the foundational engineering mandates set forth in [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md) and the operational charter in [08-autonomous-remediation-engine.md](file:///root/company-project-specs/08-autonomous-remediation-engine.md), this daemon provides autonomous, deterministic infrastructure remediation across host-local workloads on Linux ARM64, including [ai-gateway](file:///root/company-project-specs/01-ai-gateway.md) and [ai-security-guardrail-proxy](file:///root/company-project-specs/09-ai-security-guardrail-proxy.md). In accordance with [FAILURE-MODES.md](file:///root/autonomous-remediation-engine/docs/FAILURE-MODES.md), failure containment requires rigorous, continuous instrumentation of all operational transitions.

### 1.1. Cardinal Observability Rule: Decoupling Remediation Latency Stages

In autonomous infrastructure remediation, total elapsed time spans distinct mechanical phases: alert ingestion, runbook resolution, lock acquisition, precondition evaluation, action execution, postcondition verification, and journal commit.

Conflating these distinct operational phases into a single opaque duration metric obscures critical bottlenecks:
- A regression in lock contention (e.g. waiting on a deadlocked file descriptor) would be hidden within long process restart deadlines.
- Slow external health probes during postcondition verification cannot be isolated from internal engine execution overhead.
- AI-driven classification delays (when probabilistic runbook retrieval is enabled) must never pollute the deterministic execution metrics.

Therefore, the Autonomous Remediation Engine strictly segments and independently measures:

1. **Detection & Ingestion Latency ($T_{\text{detect}}$)**: Time from raw alert emission or metric threshold crossing to internal engine queue dequeue and deduplication.
2. **Lock Acquisition Time ($T_{\text{lock}}$)**: Duration required to acquire the target process/subsystem advisory lock (`flock(2)`/`fcntl(2)`).
3. **Precondition Evaluation Duration ($T_{\text{pre}}$)**: Time spent asserting ground-truth kernel invariants before executing any mutating syscalls.
4. **Action Execution Latency ($T_{\text{exec}}$)**: Physical execution time of the remediation action (e.g. signal dispatch, file truncation, atomic swap).
5. **Postcondition Verification Latency ($T_{\text{post}}$)**: Time spent verifying that the target system returned to a verified healthy operational state.
6. **Journal Durability Overhead ($T_{\text{journal}}$)**: Time required to flush the cryptographic audit record and transaction state to disk via `fsync(2)`.

```
+---------------------------------------------------------------------------------------------------------------------------------------+
| Total End-to-End Remediation Cycle (remediation_cycle_duration_seconds)                                                              |
+---------------------------------------------------------------------------------------------------------------------------------------+
| Ingestion & Dedup        | Lock & Preconditions   | Action Execution       | Postcondition Verification | Journal Flush & Commit      |
| (T_detect)               | (T_lock + T_pre)       | (T_exec)               | (T_post)                   | (T_journal)                 |
| [Debounce, Rate Limit,   | [flock acquisition,    | [pidfd_send_signal,    | [Loopback HTTP probe,      | [fsync WAL sector,          |
|  Runbook Whitelist Match]|  /proc stat checks]    |  atomic rename, drain] |  /proc status check]       |  HMAC Merkle chain append]  |
+--------------------------+------------------------+------------------------+----------------------------+-----------------------------+
|<------ p99 < 1.0s ------>|<------ < 100ms ------->|<------ < 2.0s -------->|<--------- < 1.5s --------->|<--------- < 50ms ---------->|
|<==================================== MEAN TIME TO REMEDIATE (MTTR): p95 < 5.0s =====================================================>|
```

---

## 2. Production Service Level Indicators (SLIs) and Objectives (SLOs)

The following table summarizes the six binding production Service Level Objectives for the Autonomous Remediation Engine:

| Objective ID | Objective Name | Target (30-day Rolling) | Evaluation Formula / Metric | Measurement Boundary |
| :--- | :--- | :--- | :--- | :--- |
| **SLO-MTTD-01** | Mean Time to Detect / Ingest | $p_{99} < 1.0\,\text{s}$ | $\text{Quantile}_{0.99}(T_{\text{detect}}) \le 1.0\,\text{s}$ | Ingress socket read to runbook queue pop. Excludes target wait. |
| **SLO-MTTR-01** | Mean Time to Remediate (Deterministic) | $p_{95} < 5.0\,\text{s}$ | $\text{Quantile}_{0.95}(T_{\text{remediation}}) \le 5.0\,\text{s}$ | Alert dequeue to verified postcondition completion. |
| **SLO-VER-01** | Postcondition Verification Invariant | **100.0%** ($0$ unverified) | $\frac{N_{\text{verified\_actions}}}{N_{\text{executed\_mutations}}} = 1.0000$ | Physical validation of ground truth; zero blind mutations. |
| **SLO-RBK-01** | Rollback Success Rate | $\ge 99.9\%$ ($< 1000\,\text{PPM}$) | $\frac{N_{\text{successful\_rollbacks}}}{N_{\text{triggered\_rollbacks}}} \ge 0.999$ | Reversal of failed mutations to Last-Known-Good state. |
| **SLO-FLP-01** | Flap Damping Circuit Breaker | **100.0%** enforcement | $\text{MaxActions}(W=10\text{m}) \le 3$ before lock | Target action rate limiting; circuit trips on 4th alert. |
| **SLO-AVL-01** | Remediation Daemon Availability | $\ge 99.99\%$ ($4.32\,\text{m/mo}$) | $\frac{T_{\text{uptime}} - T_{\text{unplanned\_downtime}}}{T_{\text{uptime}}} \ge 0.9999$ | Daemon loop health, socket responsive, metrics reporting. |

---

## 3. Formal Mathematical Specifications

### 3.1. Mean Time to Detect & Ingest (MTTD) SLI & SLO

#### 3.1.1. Formal Definition
The Detection & Ingestion Latency ($T_{\text{detect}}$) measures the time elapsed from the timestamp when an alert payload enters the remediation daemon's Unix domain socket or local HTTP endpoint until the runbook resolution engine completes deduplication, parses the alert schema, and assigns a deterministic runbook:

$$T_{\text{detect}} = t_{\text{resolved}} - t_{\text{received}}$$

#### 3.1.2. Percentile Latency Formulation
Let $F_{\text{MTTD}}(t)$ be the cumulative distribution function (CDF) of $T_{\text{detect}}$ over a 30-day evaluation window:

$$F_{\text{MTTD}}(t) = P(T_{\text{detect}} \le t)$$

The 99th percentile ($p_{99}$) is defined as:

$$p_{99} = \inf \{ t \in \mathbb{R} : F_{\text{MTTD}}(t) \ge 0.99 \}$$

#### 3.1.3. SLI Mathematical Formula
$$\text{SLI}_{\text{MTTD}} = \frac{\sum_{i=1}^{N_{\text{alerts}}} \mathbb{I}(T_{\text{detect}, i} \le 1.0\,\text{s})}{N_{\text{alerts}}} \ge 0.9900$$

Where $\mathbb{I}(\cdot)$ is the indicator function. Evaluated across all incoming alerts with valid JSON/Protobuf schemas.

---

### 3.2. Mean Time to Remediate (MTTR) SLI & SLO

#### 3.2.1. Formal Definition
For deterministic runbooks (such as log volume draining, zombie process restart, TLS reload, or configuration rollback), the Mean Time to Remediate ($T_{\text{remediation}}$) covers the complete lifecycle from alert dequeuing through to successful postcondition verification:

$$T_{\text{remediation}} = T_{\text{lock}} + T_{\text{pre}} + T_{\text{exec}} + T_{\text{post}} + T_{\text{journal}}$$

#### 3.2.2. Objectives
- **Median ($p_{50}$)**: $< 2.5\,\text{s}$
- **90th Percentile ($p_{90}$)**: $< 4.0\,\text{s}$
- **95th Percentile ($p_{95}$)**: $< 5.0\,\text{s}$

#### 3.2.3. SLI Mathematical Formula
$$\text{SLI}_{\text{MTTR}} = \frac{\sum_{k=1}^{N_{\text{remediations}}} \mathbb{I}(T_{\text{remediation}, k} \le 5.0\,\text{s})}{N_{\text{remediations}}} \ge 0.9500$$

*Exclusion Criteria*: Excludes runs where the target process was hung in an uninterruptible kernel sleep state (`TASK_UNINTERRUPTIBLE`) requiring human physical intervention, or where the remediation was explicitly deferred by flap damping backoff.

---

### 3.3. 100% Postcondition Verification Invariant

#### 3.3.1. Foundational Axiom
In accordance with [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md):

$$\text{\bf Automation without verification is not reliability engineering.}$$

An automated action is strictly incomplete until the system verifies its intended outcome against ground-truth operating system states. The engine enforces an unyielding invariant: **Zero unverified mutations are permitted to be committed to the audit ledger as successful.**

#### 3.3.2. Ground-Truth Verification Matrix
A postcondition is verified only if all required sub-predicates evaluate to `TRUE`:

| Runbook Domain | Physical Verification Ground Truth | Deterministic Predicate ($V_{\text{target}}$) |
| :--- | :--- | :--- |
| **Disk Log Drain** | `statvfs(2)` on mount point | $\text{FreeBytes} \ge \text{Threshold}_{\text{min}} \land \text{ActiveFDOpen} == \text{TRUE}$ |
| **Process Restart** | `/proc/[pid]/status` & TCP loopback | $\text{State} \in \{'R', 'S'\} \land \text{TCPConnect}(\text{127.0.0.1:port}) == \text{SUCCESS} \land \text{HTTPProbe}() == 200$ |
| **TLS Cert Reload** | `crypto/tls` Handshake on loopback | $\text{CertSerialNumber} == \text{NewSerial} \land \text{ValidDays} \ge 30$ |
| **Config Rollback** | Inode SHA-256 & Process Health | $\text{Hash}(/etc/config) == \text{Hash}_{\text{LKG}} \land \text{HTTPProbe}() == 200$ |

#### 3.3.3. SLI Formula
$$\text{SLI}_{\text{verification}} = \frac{N_{\text{verified\_actions}}}{N_{\text{executed\_mutations}}} \equiv 1.0000$$

Metric representation:
$$\text{remediation_unverified_mutations_total} \equiv 0$$

Any non-zero count of unverified mutations triggers an automatic Sev-1 system integrity incident and halts the remediation engine daemon.

---

### 3.4. Rollback Success Rate SLI & SLO

#### 3.4.1. Formal Definition
When an action fails during execution or fails to satisfy postcondition verification within the allocated deadline ($T_{\text{post}} \le 5.0\,\text{s}$), the engine must automatically reverse all changes using its Write-Ahead Rollback Journal. The Rollback Success Rate measures the reliability of reverting to the Last-Known-Good state without human intervention.

#### 3.4.2. Objectives
- **Target**: $\ge 99.9\%$ ($< 1$ failure per 1,000 rollback attempts).
- **Allowable Error Budget**: $0.1\%$ ($1000\,\text{PPM}$).

#### 3.4.3. SLI Mathematical Formula
$$\text{SLI}_{\text{rollback}} = \frac{N_{\text{rollbacks\_verified\_clean}}}{N_{\text{rollbacks\_triggered}}} \ge 0.9990$$

Where $N_{\text{rollbacks\_verified\_clean}}$ represents transactions where:
1. The original configuration/symlink was atomically restored.
2. The target service was restored to its prior state or quarantined safely.
3. The journal state transitions to `ABORTED` or `ROLLED_BACK`.

---

### 3.5. Flap Damping Circuit Breaker Enforceability

#### 3.5.1. Formal Definition
To prevent automated systems from thrashing infrastructure during unrecoverable systemic failures, the engine strictly enforces the **Flap Damping Invariant**:

$$\text{Max Automated Actions} \le 3 \text{ per } 10\text{-minute sliding window per target subsystem}$$

Upon the receipt of a 4th alert for the same target within a 600-second window, the remediation engine must transition the target's circuit breaker to the **LOCKED** state, suppress all further actions, and page human on-call engineers.

#### 3.5.2. Mathematical Model of Sliding Window Flap Accounting
Let $A_k(t) = \{ t_1, t_2, \dots, t_m \}$ be the set of timestamps of remediation actions executed against target $k$. The active action count $C_k(t)$ in a sliding window of length $W = 600\,\text{seconds}$ is:

$$C_k(t) = \sum_{t_i \in A_k(t)} \mathbb{I}(t - 600\,\text{s} \le t_i \le t)$$

The operational gate function $G_k(t)$ is defined as:

$$G_k(t) = \begin{cases} 
\text{PERMIT} & \text{if } C_k(t) < 3 \\
\text{CIRCUIT\_LOCK} & \text{if } C_k(t) \ge 3 
\end{cases}$$

#### 3.5.3. SLI Formula
$$\text{SLI}_{\text{flap\_enforce}} = \frac{N_{\text{flaps\_correctly\_locked}}}{N_{\text{flap\_breach\_events}}} \equiv 1.0000$$

Any execution of a 4th remediation action within 10 minutes on a single target constitutes a critical failure of the safety gate.

---

## 4. Multi-Window Multi-Burn-Rate Alerting Architecture

To protect error budgets without generating alert fatigue, the remediation engine follows the Google SRE multi-window, multi-burn-rate alerting framework.

### 4.1. Error Budget Allocation (30-Day Rolling Window)

For a target availability of $99.99\%$ and an MTTR compliance of $95.0\%$:
- **Availability Error Budget**: $0.01\% \implies 4.32\,\text{minutes of downtime per month}$.
- **MTTR Error Budget**: $5.0\% \implies 50\,\text{non-compliant actions per 1,000 runs}$.
- **Rollback Error Budget**: $0.1\% \implies 1\,\text{failed rollback per 1,000 rollback triggers}$.

### 4.2. Burn Rate Formulations & Thresholds

Burn rate $B$ represents the rate at which the error budget is being consumed relative to the allowable monthly consumption rate ($1\times$ consumption exhausts $100\%$ of the budget in exactly 30 days).

$$B = \frac{\text{Observed Error Rate}}{\text{Target Error Budget}}$$

| Alert Severity | Burn Rate ($B$) | Short Window ($W_s$) | Long Window ($W_l$) | Budget Consumed | Action / Routing |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Page (Sev-1)** | **14.4x** | 2 minutes | 1 hour | $2.0\%$ in 1 hour | Immediate PagerDuty page to primary on-call SRE. |
| **Page (Sev-2)** | **6.0x** | 15 minutes | 6 hours | $5.0\%$ in 6 hours | PagerDuty page to primary on-call SRE. |
| **Ticket (Sev-3)**| **1.0x** | 2 hours | 3 days | $10.0\%$ in 3 days | Automated JIRA/Slack ticket to platform reliability team. |

```
Burn Rate Consumption Curves (30-day budget)
Budget %
 100 |                                            / (14.4x Burn: Exhausted in 50 hours)
     |                                           /
  50 |                                          /
     |                       / (6.0x Burn)     /
  20 |                      /                 /
  10 |   / (1.0x Burn)     /                 /
   0 +---+----------------+-----------------+---------------------> Time (Days)
     0   3                10                30
```

---

## 5. Prometheus Metrics Catalog

All metrics emitted by the Autonomous Remediation Engine daemon conform to standard OpenMetrics/Prometheus formats, exposed on `http://127.0.0.1:9095/metrics`.

### 5.1. Latency & Execution Histograms

```ini
# HELP remediation_cycle_duration_seconds Total end-to-end execution time of remediation cycle.
# TYPE remediation_cycle_duration_seconds histogram
remediation_cycle_duration_seconds_bucket{target="ai-gateway",runbook="service_deadlock_restart",le="0.5"} 42
remediation_cycle_duration_seconds_bucket{target="ai-gateway",runbook="service_deadlock_restart",le="1.0"} 118
remediation_cycle_duration_seconds_bucket{target="ai-gateway",runbook="service_deadlock_restart",le="2.5"} 304
remediation_cycle_duration_seconds_bucket{target="ai-gateway",runbook="service_deadlock_restart",le="5.0"} 380
remediation_cycle_duration_seconds_bucket{target="ai-gateway",runbook="service_deadlock_restart",le="+Inf"} 382
remediation_cycle_duration_seconds_sum{target="ai-gateway",runbook="service_deadlock_restart"} 721.4
remediation_cycle_duration_seconds_count{target="ai-gateway",runbook="service_deadlock_restart"} 382

# HELP remediation_ingest_duration_seconds Latency of alert receipt, debouncing, and runbook matching.
# TYPE remediation_ingest_duration_seconds histogram
remediation_ingest_duration_seconds_bucket{le="0.05"} 1240
remediation_ingest_duration_seconds_bucket{le="0.1"} 1850
remediation_ingest_duration_seconds_bucket{le="0.5"} 2100
remediation_ingest_duration_seconds_bucket{le="1.0"} 2145
remediation_ingest_duration_seconds_bucket{le="+Inf"} 2148

# HELP remediation_lock_duration_seconds Time spent waiting for target mutual exclusion advisory lock.
# TYPE remediation_lock_duration_seconds histogram
remediation_lock_duration_seconds_bucket{target="ai-security-guardrail-proxy",le="0.01"} 350
remediation_lock_duration_seconds_bucket{target="ai-security-guardrail-proxy",le="0.1"} 380
remediation_lock_duration_seconds_bucket{target="ai-security-guardrail-proxy",le="1.0"} 382
```

### 5.2. Counters and State Gauges

```ini
# HELP remediation_actions_total Total number of remediation actions executed by target, runbook, and outcome.
# TYPE remediation_actions_total counter
remediation_actions_total{target="ai-gateway",runbook="disk_log_drain",outcome="success"} 14
remediation_actions_total{target="ai-gateway",runbook="service_deadlock_restart",outcome="success"} 5
remediation_actions_total{target="ai-security-guardrail-proxy",runbook="config_rollback",outcome="success"} 2
remediation_actions_total{target="ai-gateway",runbook="service_deadlock_restart",outcome="rollback"} 1

# HELP remediation_unverified_mutations_total INVARIANT BREACH: Actions committed without verified postconditions.
# TYPE remediation_unverified_mutations_total counter
remediation_unverified_mutations_total 0

# HELP remediation_rollbacks_total Total count of triggered rollback transactions and their outcomes.
# TYPE remediation_rollbacks_total counter
remediation_rollbacks_total{target="ai-gateway",outcome="success"} 1
remediation_rollbacks_total{target="ai-gateway",outcome="failure"} 0

# HELP remediation_circuit_breaker_state Active state of target remediation circuit breaker (0=Closed, 1=Half-Open, 2=Locked).
# TYPE remediation_circuit_breaker_state gauge
remediation_circuit_breaker_state{target="ai-gateway"} 0
remediation_circuit_breaker_state{target="ai-security-guardrail-proxy"} 0

# HELP remediation_active_locks Gauge of actively held host advisory file locks.
# TYPE remediation_active_locks gauge
remediation_active_locks{target="ai-gateway"} 0

# HELP remediation_pid_collisions_prevented_total Counter of aborted signals where PID reuse was detected via pidfd/start-time mismatch.
# TYPE remediation_pid_collisions_prevented_total counter
remediation_pid_collisions_prevented_total 0
```

---

## 6. Binding Prometheus Alerting Rules (PromQL)

The following PromQL rules must be deployed into the production Prometheus/Alertmanager rules catalog:

### 6.1. Sev-1 Critical Rules (Immediate Pager Duty)

```yaml
groups:
  - name: autonomous_remediation_slo_alerts
    rules:
      - alert: RemediationUnverifiedMutationDetected
        expr: increase(remediation_unverified_mutations_total[1m]) > 0
        for: 0m
        labels:
          severity: critical
          tier: platform-sre
        annotations:
          summary: "CRITICAL INVARIANT VIOLATION: Unverified mutation executed by autonomous remediation engine"
          description: "Remediation engine committed a state change without ground-truth postcondition verification. System integrity compromised."
          runbook_url: "file:///root/autonomous-remediation-engine/docs/OPERATIONS.md#incident-response-unverified-mutation"

      - alert: RemediationRollbackFailed
        expr: increase(remediation_rollbacks_total{outcome="failure"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
          tier: platform-sre
        annotations:
          summary: "Rollback execution failed for target {{ $labels.target }}"
          description: "Target {{ $labels.target }} failed postconditions and subsequent rollback journal replay also failed. Target in unverified quarantine."
          runbook_url: "file:///root/autonomous-remediation-engine/docs/OPERATIONS.md#incident-response-rollback-failure"

      - alert: RemediationCircuitBreakerLocked
        expr: remediation_circuit_breaker_state == 2
        for: 0m
        labels:
          severity: critical
          tier: platform-sre
        annotations:
          summary: "Circuit breaker LOCKED for target {{ $labels.target }}"
          description: "Target {{ $labels.target }} exceeded maximum allowable flapping rate (3 actions in 10 minutes). Automated remediation halted."
          runbook_url: "file:///root/autonomous-remediation-engine/docs/OPERATIONS.md#circuit-breaker-unlock-procedure"

      - alert: RemediationMTTRHighBurnRate
        expr: (
            histogram_quantile(0.95, sum(rate(remediation_cycle_duration_seconds_bucket[1h])) by (le)) > 5.0
          ) and (
            histogram_quantile(0.95, sum(rate(remediation_cycle_duration_seconds_bucket[2m])) by (le)) > 5.0
          )
        for: 2m
        labels:
          severity: critical
          tier: platform-sre
        annotations:
          summary: "MTTR SLO burn rate 14.4x exceeded"
          description: "p95 remediation latency is exceeding 5.0 seconds over 1-hour window. Fast burn rate detected."
```

### 6.2. Sev-2 Warning Rules (Slack Notification & SRE On-Call Ticket)

```yaml
      - alert: RemediationMTTDHighLatency
        expr: histogram_quantile(0.99, sum(rate(remediation_ingest_duration_seconds_bucket[5m])) by (le)) > 1.0
        for: 5m
        labels:
          severity: warning
          tier: platform-sre
        annotations:
          summary: "MTTD SLO degradation: alert ingestion latency p99 > 1.0s"
          description: "Alert ingestion queue is experiencing delays. Inspect system load and alert storm rates."
          runbook_url: "file:///root/autonomous-remediation-engine/docs/OPERATIONS.md#alert-storm-troubleshooting"

      - alert: RemediationPIDCollisionPrevented
        expr: increase(remediation_pid_collisions_prevented_total[10m]) > 0
        for: 0m
        labels:
          severity: warning
          tier: platform-sre
        annotations:
          summary: "PID recycling race condition intercepted by pidfd/stat check"
          description: "Remediation engine intercepted an alert referencing a recycled PID. Target process safely preserved from false signaling."
```
