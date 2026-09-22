package ingress

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"autonomous-remediation-engine/internal/engine"
	"autonomous-remediation-engine/internal/model"
)

// Default histogram latency buckets in seconds.
var defaultDurationBuckets = []float64{
	0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0, 30.0,
}

type histogram struct {
	buckets []float64
	counts  []uint64
	sum     float64
	total   uint64
}

func newHistogram(buckets []float64) *histogram {
	return &histogram{
		buckets: buckets,
		counts:  make([]uint64, len(buckets)),
	}
}

func (h *histogram) observe(v float64) {
	h.sum += v
	h.total++
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
}

// Metrics tracks and formats SLO and operational Prometheus metrics.
type Metrics struct {
	mu                      sync.RWMutex
	startTime               time.Time
	actionsTotal            map[string]uint64    // key: runbook\x00state
	durationHistograms      map[string]*histogram // key: runbook
	precheckFailuresTotal   map[string]uint64    // key: resource
	rollbacksTotal          map[string]uint64    // key: resource
	dampingTrippedTotal     map[string]uint64    // key: resource
}

// NewMetrics initializes an empty Prometheus metrics registry.
func NewMetrics() *Metrics {
	return &Metrics{
		startTime:             time.Now(),
		actionsTotal:          make(map[string]uint64),
		durationHistograms:    make(map[string]*histogram),
		precheckFailuresTotal: make(map[string]uint64),
		rollbacksTotal:        make(map[string]uint64),
		dampingTrippedTotal:   make(map[string]uint64),
	}
}

// RecordAction increments action counter and records duration in the histogram.
func (m *Metrics) RecordAction(runbookID, state string, duration time.Duration) {
	if runbookID == "" {
		runbookID = "unknown"
	}
	if state == "" {
		state = "UNKNOWN"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := runbookID + "\x00" + state
	m.actionsTotal[key]++

	h, ok := m.durationHistograms[runbookID]
	if !ok {
		h = newHistogram(defaultDurationBuckets)
		m.durationHistograms[runbookID] = h
	}
	h.observe(duration.Seconds())
}

// RecordPrecheckFailure increments precheck failure counter for the given resource.
func (m *Metrics) RecordPrecheckFailure(resourceID string) {
	if resourceID == "" {
		resourceID = "unknown"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.precheckFailuresTotal[resourceID]++
}

// RecordRollback increments rollback counter for the given resource.
func (m *Metrics) RecordRollback(resourceID string) {
	if resourceID == "" {
		resourceID = "unknown"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollbacksTotal[resourceID]++
}

// RecordDampingTripped increments damping circuit trip counter for the given resource.
func (m *Metrics) RecordDampingTripped(resourceID string) {
	if resourceID == "" {
		resourceID = "unknown"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dampingTrippedTotal[resourceID]++
}

// RecordRemediationResult extracts metrics from an engine.RemediationResult.
func (m *Metrics) RecordRemediationResult(res *engine.RemediationResult) {
	if res == nil {
		return
	}

	m.RecordAction(res.RunbookID, string(res.FinalState), res.Duration)

	if res.FinalState == model.StatePrecheckFailed {
		m.RecordPrecheckFailure(res.ResourceID)
	}

	if res.RolledBack || res.FinalState == model.StateRolledBack || res.FinalState == model.StateRollingBack {
		m.RecordRollback(res.ResourceID)
	}

	if strings.Contains(res.Error, "FLAP_DAMPING") || strings.Contains(res.Error, "damping") {
		m.RecordDampingTripped(res.ResourceID)
	}
}

// RenderPrometheus generates standard Prometheus exposition text format.
func (m *Metrics) RenderPrometheus() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sb strings.Builder

	// 1. remediation_actions_total
	sb.WriteString("# HELP remediation_actions_total Total number of remediation actions executed by runbook and state.\n")
	sb.WriteString("# TYPE remediation_actions_total counter\n")
	actionKeys := make([]string, 0, len(m.actionsTotal))
	for k := range m.actionsTotal {
		actionKeys = append(actionKeys, k)
	}
	sort.Strings(actionKeys)
	for _, k := range actionKeys {
		parts := strings.Split(k, "\x00")
		runbook, state := parts[0], parts[1]
		count := m.actionsTotal[k]
		sb.WriteString(fmt.Sprintf("remediation_actions_total{runbook=%q,state=%q} %d\n", runbook, state, count))
	}
	if len(actionKeys) == 0 {
		sb.WriteString("remediation_actions_total{runbook=\"none\",state=\"NONE\"} 0\n")
	}

	// 2. remediation_duration_seconds
	sb.WriteString("# HELP remediation_duration_seconds Duration of remediation actions in seconds.\n")
	sb.WriteString("# TYPE remediation_duration_seconds histogram\n")
	histRunbooks := make([]string, 0, len(m.durationHistograms))
	for r := range m.durationHistograms {
		histRunbooks = append(histRunbooks, r)
	}
	sort.Strings(histRunbooks)
	for _, r := range histRunbooks {
		h := m.durationHistograms[r]
		for i, b := range h.buckets {
			sb.WriteString(fmt.Sprintf("remediation_duration_seconds_bucket{runbook=%q,le=\"%.2f\"} %d\n", r, b, h.counts[i]))
		}
		sb.WriteString(fmt.Sprintf("remediation_duration_seconds_bucket{runbook=%q,le=\"+Inf\"} %d\n", r, h.total))
		sb.WriteString(fmt.Sprintf("remediation_duration_seconds_sum{runbook=%q} %.6f\n", r, h.sum))
		sb.WriteString(fmt.Sprintf("remediation_duration_seconds_count{runbook=%q} %d\n", r, h.total))
	}
	if len(histRunbooks) == 0 {
		sb.WriteString("remediation_duration_seconds_bucket{runbook=\"none\",le=\"+Inf\"} 0\n")
		sb.WriteString("remediation_duration_seconds_sum{runbook=\"none\"} 0.000000\n")
		sb.WriteString("remediation_duration_seconds_count{runbook=\"none\"} 0\n")
	}

	// 3. remediation_precheck_failures_total
	sb.WriteString("# HELP remediation_precheck_failures_total Total count of precheck invariant failures.\n")
	sb.WriteString("# TYPE remediation_precheck_failures_total counter\n")
	preKeys := sortedKeys(m.precheckFailuresTotal)
	for _, res := range preKeys {
		sb.WriteString(fmt.Sprintf("remediation_precheck_failures_total{resource=%q} %d\n", res, m.precheckFailuresTotal[res]))
	}
	if len(preKeys) == 0 {
		sb.WriteString("remediation_precheck_failures_total{resource=\"none\"} 0\n")
	}

	// 4. remediation_rollbacks_total
	sb.WriteString("# HELP remediation_rollbacks_total Total count of triggered rollback transactions.\n")
	sb.WriteString("# TYPE remediation_rollbacks_total counter\n")
	rbKeys := sortedKeys(m.rollbacksTotal)
	for _, res := range rbKeys {
		sb.WriteString(fmt.Sprintf("remediation_rollbacks_total{resource=%q} %d\n", res, m.rollbacksTotal[res]))
	}
	if len(rbKeys) == 0 {
		sb.WriteString("remediation_rollbacks_total{resource=\"none\"} 0\n")
	}

	// 5. remediation_damping_tripped_total
	sb.WriteString("# HELP remediation_damping_tripped_total Total count of flap damping circuit breaker trips.\n")
	sb.WriteString("# TYPE remediation_damping_tripped_total counter\n")
	dampKeys := sortedKeys(m.dampingTrippedTotal)
	for _, res := range dampKeys {
		sb.WriteString(fmt.Sprintf("remediation_damping_tripped_total{resource=%q} %d\n", res, m.dampingTrippedTotal[res]))
	}
	if len(dampKeys) == 0 {
		sb.WriteString("remediation_damping_tripped_total{resource=\"none\"} 0\n")
	}

	// 6. remediation_daemon_uptime_seconds
	uptime := time.Since(m.startTime).Seconds()
	sb.WriteString("# HELP remediation_daemon_uptime_seconds Uptime of the autonomous remediation daemon in seconds.\n")
	sb.WriteString("# TYPE remediation_daemon_uptime_seconds gauge\n")
	sb.WriteString(fmt.Sprintf("remediation_daemon_uptime_seconds %.2f\n", uptime))

	return sb.String()
}

func sortedKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
