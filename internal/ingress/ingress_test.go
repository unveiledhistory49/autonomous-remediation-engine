package ingress

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"autonomous-remediation-engine/internal/audit"
	"autonomous-remediation-engine/internal/config"
	"autonomous-remediation-engine/internal/damping"
	"autonomous-remediation-engine/internal/engine"
	"autonomous-remediation-engine/internal/model"
)

// mockEngine implements EngineProvider for testing.
type mockEngine struct {
	healthy      bool
	healthReason string
	runbooks     []*model.Runbook
	ledger       *audit.Ledger
	damping      *damping.Controller
	received     []*model.Alert
	processFn    func(alert *model.Alert) (*engine.RemediationResult, error)
}

func (m *mockEngine) ProcessAlert(alert *model.Alert) (*engine.RemediationResult, error) {
	m.received = append(m.received, alert)
	if m.processFn != nil {
		return m.processFn(alert)
	}
	return &engine.RemediationResult{
		TxID:        "tx-test-1",
		RunbookID:   alert.Labels["runbook_id"],
		ResourceID:  alert.ResourceID,
		FinalState:  model.StateCommitted,
		Success:     true,
		Duration:    10 * time.Millisecond,
		Transitions: []model.StateTransition{},
	}, nil
}

func (m *mockEngine) IsHealthy() (bool, string) {
	return m.healthy, m.healthReason
}

func (m *mockEngine) ListRunbooks() []*model.Runbook {
	return m.runbooks
}

func (m *mockEngine) Damping() *damping.Controller {
	return m.damping
}

func (m *mockEngine) Ledger() *audit.Ledger {
	return m.ledger
}

func TestUnixSocket_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test-ingress.sock")

	mockEng := &mockEngine{healthy: true}
	metrics := NewMetrics()

	server := NewUnixSocketServer(sockPath, mockEng, metrics)
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start unix socket server: %v", err)
	}

	// Verify file permissions 0660
	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("failed to stat socket file: %v", err)
	}
	if info.Mode().Perm() != 0660 {
		t.Errorf("expected socket permissions 0660, got %o", info.Mode().Perm())
	}

	// Connect and send an alert
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial unix socket: %v", err)
	}
	defer conn.Close()

	testAlert := model.Alert{
		ID:          "alert-sock-001",
		Fingerprint: "fp-sock-001",
		ResourceID:  "/var/log",
		Severity:    model.SeverityHigh,
		Labels: map[string]string{
			"runbook_id": "RBK-DISK-001",
		},
		ReceivedAt: time.Now().UTC(),
	}

	if err := json.NewEncoder(conn).Encode(testAlert); err != nil {
		t.Fatalf("failed to write alert to unix socket: %v", err)
	}

	var res engine.RemediationResult
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		t.Fatalf("failed to decode response from unix socket: %v", err)
	}

	if res.FinalState != model.StateCommitted {
		t.Errorf("expected final state COMMITTED, got %s", res.FinalState)
	}
	if res.ResourceID != "/var/log" {
		t.Errorf("expected resource /var/log, got %s", res.ResourceID)
	}

	// Stop server and verify socket removal
	if err := server.Stop(); err != nil {
		t.Fatalf("failed to stop unix socket server: %v", err)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected socket file to be removed on shutdown, err: %v", err)
	}
}

func TestHTTPServer_WebhooksAndHMAC(t *testing.T) {
	secret := "test-secret-hmac-key-2026"
	metrics := NewMetrics()
	mockEng := &mockEngine{healthy: true}

	server := NewHTTPServer("127.0.0.1:0", secret, mockEng, metrics)
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start HTTP server: %v", err)
	}
	defer server.Stop(context.Background())

	baseURL := fmt.Sprintf("http://%s", server.Addr())

	alert := model.Alert{
		ID:          "alert-http-001",
		ResourceID:  "ai-gateway",
		Severity:    model.SeverityCritical,
		Labels:      map[string]string{"runbook_id": "RBK-PROC-001"},
		ReceivedAt: time.Now().UTC(),
	}
	alertBytes, _ := json.Marshal(alert)

	computeHMAC := func(payload []byte, key string) string {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write(payload)
		return hex.EncodeToString(mac.Sum(nil))
	}

	// 1. Missing signature header -> 401 Unauthorized
	req, _ := http.NewRequest("POST", baseURL+"/v1/alerts", bytes.NewReader(alertBytes))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401 for missing signature, got %d", resp.StatusCode)
	}

	// 2. Invalid signature -> 401 Unauthorized
	req, _ = http.NewRequest("POST", baseURL+"/v1/alerts", bytes.NewReader(alertBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-256", "invalidhexsignature123")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401 for invalid signature, got %d", resp.StatusCode)
	}

	// 3. Valid signature in X-Signature-256 -> 200 OK
	validSig := computeHMAC(alertBytes, secret)
	req, _ = http.NewRequest("POST", baseURL+"/v1/alerts", bytes.NewReader(alertBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-256", validSig)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 for valid signature, got %d", resp.StatusCode)
	}
	var res engine.RemediationResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res.FinalState != model.StateCommitted {
		t.Errorf("expected state COMMITTED, got %s", res.FinalState)
	}

	// 4. Malformed JSON -> 400 Bad Request
	badJSON := []byte(`{"id": 123, "malformed"`)
	badSig := computeHMAC(badJSON, secret)
	req, _ = http.NewRequest("POST", baseURL+"/v1/alerts", bytes.NewReader(badJSON))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-256", badSig)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for malformed JSON, got %d", resp.StatusCode)
	}

	// 5. Unprocessable entity (missing ID/ResourceID) -> 422 Unprocessable Entity
	emptyAlert := []byte(`{"id": "", "resource_id": ""}`)
	emptySig := computeHMAC(emptyAlert, secret)
	req, _ = http.NewRequest("POST", baseURL+"/v1/alerts", bytes.NewReader(emptyAlert))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-256", emptySig)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422 for unprocessable entity, got %d", resp.StatusCode)
	}
}

func TestHTTPServer_HealthStatusAndMetrics(t *testing.T) {
	metrics := NewMetrics()
	tmpDir := t.TempDir()

	ledger, err := audit.NewLedger(filepath.Join(tmpDir, "audit.wal"), "test-host")
	if err != nil {
		t.Fatalf("failed to create ledger: %v", err)
	}
	defer ledger.Close()

	dampCtrl, err := damping.NewController(filepath.Join(tmpDir, "damping.json"))
	if err != nil {
		t.Fatalf("failed to create damping controller: %v", err)
	}

	mockEng := &mockEngine{
		healthy: true,
		ledger:  ledger,
		damping: dampCtrl,
		runbooks: []*model.Runbook{
			{ID: "RBK-DISK-001", Name: "disk_cleanup", TargetResourceID: "/var/log", Severity: model.SeverityHigh},
		},
	}

	server := NewHTTPServer("127.0.0.1:0", "", mockEng, metrics)
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start HTTP server: %v", err)
	}
	defer server.Stop(context.Background())

	baseURL := fmt.Sprintf("http://%s", server.Addr())

	// 1. GET /healthz (healthy)
	resp, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /healthz, got %d", resp.StatusCode)
	}

	// 2. GET /healthz (unhealthy)
	mockEng.healthy = false
	mockEng.healthReason = "lock directory not writable"
	respUnhealthy, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer respUnhealthy.Body.Close()
	if respUnhealthy.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable for /healthz when unhealthy, got %d", respUnhealthy.StatusCode)
	}
	mockEng.healthy = true

	// 3. GET /v1/status
	respStatus, err := http.Get(baseURL + "/v1/status")
	if err != nil {
		t.Fatalf("GET /v1/status failed: %v", err)
	}
	defer respStatus.Body.Close()
	if respStatus.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /v1/status, got %d", respStatus.StatusCode)
	}
	var statusData map[string]any
	if err := json.NewDecoder(respStatus.Body).Decode(&statusData); err != nil {
		t.Fatalf("failed to parse /v1/status JSON: %v", err)
	}
	if statusData["status"] != "running" {
		t.Errorf("expected status 'running', got %v", statusData["status"])
	}
	if _, ok := statusData["active_runbooks"]; !ok {
		t.Errorf("missing active_runbooks in status")
	}
	if _, ok := statusData["latest_audit_hash"]; !ok {
		t.Errorf("missing latest_audit_hash in status")
	}

	// 4. GET /metrics
	metrics.RecordAction("RBK-DISK-001", "COMMITTED", 25*time.Millisecond)
	metrics.RecordPrecheckFailure("/var/log")
	metrics.RecordRollback("ai-gateway")
	metrics.RecordDampingTripped("guardrail-proxy")

	respMetrics, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer respMetrics.Body.Close()
	if respMetrics.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /metrics, got %d", respMetrics.StatusCode)
	}

	metricsBody, _ := io.ReadAll(respMetrics.Body)
	mText := string(metricsBody)

	requiredMetrics := []string{
		"remediation_actions_total",
		"remediation_duration_seconds",
		"remediation_precheck_failures_total",
		"remediation_rollbacks_total",
		"remediation_damping_tripped_total",
		"remediation_daemon_uptime_seconds",
	}

	for _, rm := range requiredMetrics {
		if !strings.Contains(mText, rm) {
			t.Errorf("metrics output missing expected metric %s\nOutput:\n%s", rm, mText)
		}
	}
}

func TestPoller_AlertDispatch(t *testing.T) {
	mockEng := &mockEngine{healthy: true}
	metrics := NewMetrics()

	// Monitored path: /nonexistent-path-pressure (guaranteed to breach)
	// and a dummy test server for service check
	paths := []config.PathConfig{
		{
			Path:       "/nonexistent-path-for-failure-trigger",
			MinFreePct: 99.9, // extremely high threshold triggers alert on root /
		},
	}

	// Mock unhealthy service
	services := []config.ServiceConfig{
		{
			Name:      "test-hang-svc",
			HealthURL: "http://127.0.0.1:54321/dead-healthz", // dead port
			Port:      54321,
		},
	}

	poller := NewPoller(100*time.Millisecond, paths, services, mockEng, metrics)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Execute single poll pass
	poller.PollOnce(ctx)

	if len(mockEng.received) < 2 {
		t.Fatalf("expected at least 2 alerts dispatched from poller (1 disk, 1 svc), got %d", len(mockEng.received))
	}

	var foundDisk, foundSvc bool
	for _, a := range mockEng.received {
		if a.Labels["alertname"] == "DiskVolumeSaturation" {
			foundDisk = true
			if a.ResourceID != "/nonexistent-path-for-failure-trigger" {
				t.Errorf("unexpected resource for disk alert: %s", a.ResourceID)
			}
		}
		if a.Labels["alertname"] == "ServiceUnhealthyDeadlock" {
			foundSvc = true
			if a.ResourceID != "test-hang-svc" {
				t.Errorf("unexpected resource for svc alert: %s", a.ResourceID)
			}
		}
	}

	if !foundDisk {
		t.Errorf("expected DiskVolumeSaturation alert from poller")
	}
	if !foundSvc {
		t.Errorf("expected ServiceUnhealthyDeadlock alert from poller")
	}

	// Start background loop and test Stop
	if err := poller.Start(ctx); err != nil {
		t.Fatalf("failed to start poller: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	poller.Stop()
}
