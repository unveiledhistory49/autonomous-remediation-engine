package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"autonomous-remediation-engine/internal/audit"
	"autonomous-remediation-engine/internal/config"
	"autonomous-remediation-engine/internal/engine"
	"autonomous-remediation-engine/internal/model"
)

func TestDaemon_EndToEndLifecycle(t *testing.T) {
	tmpDir := t.TempDir()

	sockPath := filepath.Join(tmpDir, "daemon.sock")
	auditLog := filepath.Join(tmpDir, "audit.wal")
	lockDir := filepath.Join(tmpDir, "locks")
	journalDir := filepath.Join(tmpDir, "journal")
	dampingFile := filepath.Join(tmpDir, "damping.json")

	secret := "daemon-test-hmac-secret-999"

	cfg := &config.Config{
		UnixSocketPath:   sockPath,
		HTTPAddr:         "127.0.0.1:0", // allocate free ephemeral port
		HMACSecret:       secret,
		AuditLogPath:     auditLog,
		LockDir:          lockDir,
		JournalDir:       journalDir,
		DampingStateFile: dampingFile,
		HostUUID:         "daemon-test-node",
		PollInterval:     100 * time.Millisecond,
		MonitoredServices: []config.ServiceConfig{
			{Name: "ai-gateway", HealthURL: "http://127.0.0.1:65432/healthz", Port: 65432},
		},
		MonitoredPaths: []config.PathConfig{
			{Path: tmpDir, MinFreePct: 1.0},
		},
	}

	var logBuf bytes.Buffer
	logger := log.New(&logBuf, "[test-daemon] ", log.LstdFlags)

	daemon, err := NewDaemon(cfg, logger)
	if err != nil {
		t.Fatalf("failed to instantiate daemon: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := daemon.Start(ctx); err != nil {
		t.Fatalf("failed to start daemon: %v", err)
	}

	// 1. Test /healthz
	baseURL := fmt.Sprintf("http://%s", daemon.httpServer.Addr())
	resp, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /healthz, got %d", resp.StatusCode)
	}

	// 2. Test HTTP Alert Submission with HMAC
	httpAlert := model.Alert{
		ID:          "alert-daemon-http",
		Fingerprint: "fp-daemon-http",
		ResourceID:  tmpDir,
		Severity:    model.SeverityHigh,
		Labels: map[string]string{
			"runbook_id": "RBK-DISK-001",
		},
		ReceivedAt: time.Now().UTC(),
	}
	alertBytes, _ := json.Marshal(httpAlert)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(alertBytes)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, _ := http.NewRequest("POST", baseURL+"/v1/alerts", bytes.NewReader(alertBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-256", sig)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/alerts failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200 OK from /v1/alerts, got %d, body: %s", resp.StatusCode, string(body))
	}

	var res engine.RemediationResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode execution result: %v", err)
	}
	if res.ResourceID != tmpDir {
		t.Errorf("expected resource %s, got %s", tmpDir, res.ResourceID)
	}

	// 3. Test Unix Socket Alert Submission
	sockConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to connect to unix domain socket: %v", err)
	}

	sockAlert := model.Alert{
		ID:          "alert-daemon-sock",
		Fingerprint: "fp-daemon-sock",
		ResourceID:  "ai-gateway",
		Severity:    model.SeverityCritical,
		Labels: map[string]string{
			"runbook_id": "RBK-PROC-001",
		},
		ReceivedAt: time.Now().UTC(),
	}

	if err := json.NewEncoder(sockConn).Encode(sockAlert); err != nil {
		t.Fatalf("failed to write alert to unix socket: %v", err)
	}

	var sockRes engine.RemediationResult
	if err := json.NewDecoder(sockConn).Decode(&sockRes); err != nil {
		t.Fatalf("failed to decode result from unix socket: %v", err)
	}
	sockConn.Close()

	if sockRes.ResourceID != "ai-gateway" {
		t.Errorf("expected resource ai-gateway, got %s", sockRes.ResourceID)
	}

	// 4. Test /v1/status
	resp, err = http.Get(baseURL + "/v1/status")
	if err != nil {
		t.Fatalf("GET /v1/status failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /v1/status, got %d", resp.StatusCode)
	}
	var statusData map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&statusData); err != nil {
		t.Fatalf("failed to decode /v1/status response: %v", err)
	}
	if statusData["status"] != "running" {
		t.Errorf("expected status 'running', got %v", statusData["status"])
	}

	// 5. Test /metrics
	resp, err = http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer resp.Body.Close()
	metricsBytes, _ := io.ReadAll(resp.Body)
	metricsStr := string(metricsBytes)

	if !strings.Contains(metricsStr, "remediation_actions_total") {
		t.Errorf("expected metrics to contain remediation_actions_total")
	}
	if !strings.Contains(metricsStr, "remediation_daemon_uptime_seconds") {
		t.Errorf("expected metrics to contain remediation_daemon_uptime_seconds")
	}

	// 6. Test Graceful Shutdown
	cancel()
	if err := daemon.Stop(); err != nil {
		t.Fatalf("failed to stop daemon: %v", err)
	}

	// Verify socket file was unlinked
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected socket file %s to be unlinked after shutdown", sockPath)
	}

	// Verify audit ledger integrity
	report, err := audit.VerifyLedgerFile(auditLog)
	if err != nil {
		t.Fatalf("audit ledger verification failed after shutdown: %v", err)
	}
	if !report.Valid {
		t.Errorf("expected audit ledger to be valid")
	}
	if report.TotalRecords < 2 {
		t.Errorf("expected at least 2 audit entries, got %d", report.TotalRecords)
	}
}

func TestDaemon_SignalHandling(t *testing.T) {
	tmpDir := t.TempDir()

	sockPath := filepath.Join(tmpDir, "daemon-sig.sock")
	auditLog := filepath.Join(tmpDir, "audit-sig.wal")

	cfg := &config.Config{
		UnixSocketPath:   sockPath,
		HTTPAddr:         "127.0.0.1:0",
		AuditLogPath:     auditLog,
		LockDir:          filepath.Join(tmpDir, "locks"),
		JournalDir:       filepath.Join(tmpDir, "journal"),
		DampingStateFile: filepath.Join(tmpDir, "damping.json"),
		HostUUID:         "sig-test-node",
		PollInterval:     500 * time.Millisecond,
	}

	daemon, err := NewDaemon(cfg, nil)
	if err != nil {
		t.Fatalf("failed to instantiate daemon: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := daemon.Start(ctx); err != nil {
		t.Fatalf("failed to start daemon: %v", err)
	}

	// Simulate SIGTERM received
	sigChan := make(chan os.Signal, 1)
	sigChan <- syscall.SIGTERM

	select {
	case sig := <-sigChan:
		if sig != syscall.SIGTERM {
			t.Errorf("expected SIGTERM, got %v", sig)
		}
		cancel()
		if err := daemon.Stop(); err != nil {
			t.Fatalf("shutdown on SIGTERM failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for signal simulation")
	}

	// Socket must be unlinked
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("socket file was not unlinked on shutdown")
	}
}
