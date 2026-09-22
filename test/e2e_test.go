package test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"autonomous-remediation-engine/internal/audit"
	"autonomous-remediation-engine/internal/engine"
	"autonomous-remediation-engine/internal/model"
	"autonomous-remediation-engine/internal/runbooks"
)

func generateTestCertAndKey(t *testing.T, validDuration time.Duration, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			Organization: []string{"E2E Test Corp"},
			CommonName:   "127.0.0.1",
		},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(validDuration),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed generating certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

func computeHMAC(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestEndToEndRemediationEngine(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Setup isolated file hierarchy
	sockPath := filepath.Join(tmpDir, "remediation.sock")
	auditLog := filepath.Join(tmpDir, "audit.wal")
	lockDir := filepath.Join(tmpDir, "locks")
	journalDir := filepath.Join(tmpDir, "journal")
	dampingFile := filepath.Join(tmpDir, "damping.json")
	logDir := filepath.Join(tmpDir, "logs")
	configDir := filepath.Join(tmpDir, "etc")
	lkgDir := filepath.Join(tmpDir, "lkg")
	stagingDir := filepath.Join(tmpDir, "staging")
	sslCertsDir := filepath.Join(tmpDir, "ssl", "certs")
	sslKeyDir := filepath.Join(tmpDir, "ssl", "private")

	for _, d := range []string{lockDir, journalDir, logDir, configDir, lkgDir, stagingDir, sslCertsDir, sslKeyDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("failed creating directory %s: %v", d, err)
		}
	}

	secret := "e2e-test-hmac-secret-xyz-987"
	httpPort := getFreePort(t)
	httpAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	mockSvcPort := getFreePort(t)

	// Mock supervised service for the poller
	var mockMu sync.Mutex
	mockHealthStatus := http.StatusOK
	mockMux := http.NewServeMux()
	mockMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		mockMu.Lock()
		defer mockMu.Unlock()
		w.WriteHeader(mockHealthStatus)
		_, _ = w.Write([]byte("OK"))
	})
	mockServer := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", mockSvcPort),
		Handler: mockMux,
	}
	mockListener, err := net.Listen("tcp", mockServer.Addr)
	if err != nil {
		t.Fatalf("failed to start mock service listener: %v", err)
	}
	go func() {
		_ = mockServer.Serve(mockListener)
	}()
	defer mockServer.Close()

	// 2. Write Daemon YAML Configuration
	cfgContent := fmt.Sprintf(`unix_socket_path: %s
http_addr: %s
hmac_secret: %s
audit_log_path: %s
lock_dir: %s
journal_dir: %s
damping_state_file: %s
host_uuid: e2e-test-node
poll_interval: 200ms
monitored_services:
  - name: e2e-mock-gateway
    health_url: http://127.0.0.1:%d/healthz
    port: %d
monitored_paths:
  - path: %s
    min_free_pct: 0.1
`, sockPath, httpAddr, secret, auditLog, lockDir, journalDir, dampingFile, mockSvcPort, mockSvcPort, logDir)

	cfgPath := filepath.Join(tmpDir, "daemon-config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		t.Fatalf("failed to write daemon config: %v", err)
	}

	// 3. Compile or find binaries
	binDir := filepath.Join(tmpDir, "bin")
	_ = os.MkdirAll(binDir, 0755)
	daemonBin := filepath.Join(binDir, "remediation-daemon")

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("failed to determine repo root: %v", err)
	}

	buildCmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", daemonBin, "./cmd/remediation-daemon")
	buildCmd.Dir = repoRoot
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed building daemon binary: %v, output: %s", err, string(out))
	}

	// 4. Boot remediation-daemon process
	daemonCmd := exec.Command(daemonBin, "--config", cfgPath)
	daemonCmd.Dir = tmpDir
	daemonCmd.Env = append(os.Environ(), "REMEDIATION_ENV=test")

	var daemonStdout bytes.Buffer
	daemonCmd.Stdout = &daemonStdout
	daemonCmd.Stderr = &daemonStdout

	if err := daemonCmd.Start(); err != nil {
		t.Fatalf("failed starting remediation-daemon: %v", err)
	}

	daemonExited := make(chan struct{})
	go func() {
		_ = daemonCmd.Wait()
		close(daemonExited)
	}()

	// Cleanup daemon process when test finishes
	defer func() {
		if daemonCmd.Process != nil {
			_ = daemonCmd.Process.Signal(syscall.SIGKILL)
		}
	}()

	// 5. Wait for daemon to be ready (poll /healthz)
	baseURL := fmt.Sprintf("http://%s", httpAddr)
	ready := false
	for i := 0; i < 40; i++ {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("daemon failed to become ready at %s within 4s. Output:\n%s", baseURL, daemonStdout.String())
	}

	// -------------------------------------------------------------------------
	// Verification 1: Ingress over HTTP Webhook with HMAC
	// -------------------------------------------------------------------------
	t.Run("HTTP_Webhook_Ingress_And_HMAC", func(t *testing.T) {
		alert := model.Alert{
			ID:          "alert-http-001",
			Fingerprint: "fp-http-001",
			ResourceID:  logDir,
			Severity:    model.SeverityHigh,
			Labels: map[string]string{
				"runbook_id": "RBK-DISK-001",
			},
			ReceivedAt: time.Now().UTC(),
		}
		payload, _ := json.Marshal(alert)

		// A. Valid HMAC
		validSig := computeHMAC(secret, payload)
		req, _ := http.NewRequest("POST", baseURL+"/v1/alerts", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Signature-256", validSig)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("valid alert request failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected HTTP 200 for valid HMAC, got %d: %s", resp.StatusCode, string(body))
		}

		var res engine.RemediationResult
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatalf("failed decoding execution result: %v", err)
		}
		if res.ResourceID != logDir {
			t.Errorf("expected resource %s, got %s", logDir, res.ResourceID)
		}

		// B. Invalid HMAC signature (Fail-Closed)
		reqBad, _ := http.NewRequest("POST", baseURL+"/v1/alerts", bytes.NewReader(payload))
		reqBad.Header.Set("Content-Type", "application/json")
		reqBad.Header.Set("X-Signature-256", "invalid-forged-signature-0000000000000000")
		respBad, err := http.DefaultClient.Do(reqBad)
		if err != nil {
			t.Fatalf("bad alert request failed: %v", err)
		}
		respBad.Body.Close()
		if respBad.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for forged HMAC, got %d", respBad.StatusCode)
		}
	})

	// -------------------------------------------------------------------------
	// Verification 2: Ingress over Unix Domain Socket
	// -------------------------------------------------------------------------
	t.Run("Unix_Domain_Socket_Ingress", func(t *testing.T) {
		// Verify socket exists
		if _, err := os.Stat(sockPath); err != nil {
			t.Fatalf("unix socket not found: %v", err)
		}

		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("failed dialing unix socket: %v", err)
		}
		defer conn.Close()

		sockAlert := model.Alert{
			ID:          "alert-sock-002",
			Fingerprint: "fp-sock-002",
			ResourceID:  logDir,
			Severity:    model.SeverityHigh,
			Labels: map[string]string{
				"runbook_id": "RBK-DISK-001",
			},
			ReceivedAt: time.Now().UTC(),
		}

		if err := json.NewEncoder(conn).Encode(sockAlert); err != nil {
			t.Fatalf("failed writing alert to socket: %v", err)
		}

		var sockRes engine.RemediationResult
		if err := json.NewDecoder(conn).Decode(&sockRes); err != nil {
			t.Fatalf("failed decoding socket response: %v", err)
		}

		if sockRes.ResourceID != logDir {
			t.Errorf("expected resource %s, got %s", logDir, sockRes.ResourceID)
		}
	})

	// -------------------------------------------------------------------------
	// Verification 3: Background Poller Health Monitoring
	// -------------------------------------------------------------------------
	t.Run("Background_Poller_Supervision", func(t *testing.T) {
		// Flip mock service status to 500 Internal Server Error
		mockMu.Lock()
		mockHealthStatus = http.StatusInternalServerError
		mockMu.Unlock()

		// Wait for poller interval (200ms) to detect anomaly
		time.Sleep(600 * time.Millisecond)

		// Restore mock service to healthy
		mockMu.Lock()
		mockHealthStatus = http.StatusOK
		mockMu.Unlock()

		// Query /metrics to confirm poller recorded alerts or evaluations
		resp, err := http.Get(baseURL + "/metrics")
		if err != nil {
			t.Fatalf("failed querying metrics: %v", err)
		}
		defer resp.Body.Close()
		metricsData, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(metricsData), "remediation_actions_total") {
			t.Errorf("expected metrics to record remediation activity")
		}
	})

	// -------------------------------------------------------------------------
	// Verification 4: Runbook 1 - Disk Volume Saturation & Safe Log Drain
	// -------------------------------------------------------------------------
	t.Run("Runbook_DiskCleanup", func(t *testing.T) {
		engCfg := engine.EngineConfig{
			LockDir:          filepath.Join(tmpDir, "locks-rb1"),
			AuditLogPath:     filepath.Join(tmpDir, "audit-rb1.wal"),
			JournalDir:       filepath.Join(tmpDir, "journal-rb1"),
			DampingStatePath: filepath.Join(tmpDir, "damping-rb1.json"),
			HostUUID:         "e2e-rb1-node",
		}
		eng, err := engine.NewEngine(engCfg)
		if err != nil {
			t.Fatalf("failed creating engine: %v", err)
		}
		defer eng.Close()

		rbLogDir := filepath.Join(tmpDir, "rb1-logs")
		_ = os.MkdirAll(rbLogDir, 0755)

		activeFile := filepath.Join(rbLogDir, "ai-gateway.log")
		if err := os.WriteFile(activeFile, []byte("active-log-entry\n"), 0644); err != nil {
			t.Fatalf("failed writing active log: %v", err)
		}
		activeStat, _ := os.Stat(activeFile)
		activeInode := activeStat.Sys().(*syscall.Stat_t).Ino

		// Create 3 expired archives
		for i := 1; i <= 3; i++ {
			p := filepath.Join(rbLogDir, fmt.Sprintf("ai-gateway.log.2026-09-%02d.gz", i))
			_ = os.WriteFile(p, []byte("archive"), 0644)
			past := time.Now().Add(-72 * time.Hour)
			_ = os.Chtimes(p, past, past)
		}

		rb := runbooks.NewDiskCleanupRunbook(runbooks.DiskCleanupConfig{
			TargetDir:          rbLogDir,
			ActiveLogName:      "ai-gateway.log",
			MinFreePctRequired: 0.0,
			MaxFilesToDelete:   10,
			MaxBytesToDelete:   500 * 1024 * 1024,
			ExecutionTimeout:   5 * time.Second,
		})
		_ = eng.RegisterRunbook(rb)

		res, err := eng.RunDirect(context.Background(), rb.ID, rbLogDir)
		if err != nil {
			t.Fatalf("disk cleanup runbook failed: %v", err)
		}
		if res.FinalState != model.StateCommitted {
			t.Fatalf("expected state COMMITTED, got %s", res.FinalState)
		}

		// Verify active log was preserved
		curStat, err := os.Stat(activeFile)
		if err != nil {
			t.Fatalf("active log was deleted")
		}
		if curStat.Sys().(*syscall.Stat_t).Ino != activeInode {
			t.Errorf("active log inode modified")
		}

		// Verify archives were pruned
		entries, _ := os.ReadDir(rbLogDir)
		if len(entries) != 1 {
			t.Errorf("expected only active log remaining, found %d files", len(entries))
		}
	})

	// -------------------------------------------------------------------------
	// Verification 5: Runbook 2 - Process Deadlock Recovery & SIGKILL Ladder
	// -------------------------------------------------------------------------
	t.Run("Runbook_ServiceHangRecovery", func(t *testing.T) {
		engCfg := engine.EngineConfig{
			LockDir:          filepath.Join(tmpDir, "locks-rb2"),
			AuditLogPath:     filepath.Join(tmpDir, "audit-rb2.wal"),
			JournalDir:       filepath.Join(tmpDir, "journal-rb2"),
			DampingStatePath: filepath.Join(tmpDir, "damping-rb2.json"),
			HostUUID:         "e2e-rb2-node",
		}
		eng, err := engine.NewEngine(engCfg)
		if err != nil {
			t.Fatalf("failed creating engine: %v", err)
		}
		defer eng.Close()

		svcPort := getFreePort(t)
		svcAddr := fmt.Sprintf("127.0.0.1:%d", svcPort)
		svcHealthURL := fmt.Sprintf("http://%s/healthz", svcAddr)

		// Spawn replacement service when requested
		var replacementServer *http.Server
		var dummyCmd *exec.Cmd
		spawnFn := func() (int, error) {
			mux := http.NewServeMux()
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("HEALTHY_RESTORED"))
			})
			replacementServer = &http.Server{Addr: svcAddr, Handler: mux}
			l, err := net.Listen("tcp", svcAddr)
			if err != nil {
				return 0, err
			}
			go func() {
				_ = replacementServer.Serve(l)
			}()

			dummyCmd = exec.Command("sleep", "30")
			if err := dummyCmd.Start(); err != nil {
				return 0, err
			}
			return dummyCmd.Process.Pid, nil
		}
		defer func() {
			if replacementServer != nil {
				_ = replacementServer.Close()
			}
			if dummyCmd != nil && dummyCmd.Process != nil {
				_ = dummyCmd.Process.Kill()
			}
		}()

		rb := runbooks.NewServiceHangRecoveryRunbook(runbooks.ServiceHangConfig{
			ServiceName:      "ai-gateway",
			PIDFilePath:      filepath.Join(tmpDir, "ai-gateway-rb2.pid"),
			Port:             svcPort,
			HealthURL:        svcHealthURL,
			TargetPID:        0,
			SpawnFn:          spawnFn,
			TermTimeout:      1 * time.Second,
			KillTimeout:      1 * time.Second,
			ExecutionTimeout: 5 * time.Second,
		})
		_ = eng.RegisterRunbook(rb)

		res, err := eng.RunDirect(context.Background(), rb.ID, "ai-gateway")
		if err != nil {
			t.Fatalf("service hang recovery failed: %v", err)
		}
		if res.FinalState != model.StateCommitted {
			t.Fatalf("expected state COMMITTED, got %s", res.FinalState)
		}

		// Verify health check returns 200 OK
		resp, err := http.Get(svcHealthURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("recovered service health probe failed: %v", err)
		}
		if resp != nil {
			resp.Body.Close()
		}
	})

	// -------------------------------------------------------------------------
	// Verification 6: Runbook 3 - TLS Certificate Hot Rotation
	// -------------------------------------------------------------------------
	t.Run("Runbook_TLSCertRotation", func(t *testing.T) {
		engCfg := engine.EngineConfig{
			LockDir:          filepath.Join(tmpDir, "locks-rb3"),
			AuditLogPath:     filepath.Join(tmpDir, "audit-rb3.wal"),
			JournalDir:       filepath.Join(tmpDir, "journal-rb3"),
			DampingStatePath: filepath.Join(tmpDir, "damping-rb3.json"),
			HostUUID:         "e2e-rb3-node",
		}
		eng, err := engine.NewEngine(engCfg)
		if err != nil {
			t.Fatalf("failed creating engine: %v", err)
		}
		defer eng.Close()

		tlsPort := getFreePort(t)
		tlsAddr := fmt.Sprintf("127.0.0.1:%d", tlsPort)

		actCertPath := filepath.Join(sslCertsDir, "active.crt")
		actKeyPath := filepath.Join(sslKeyDir, "active.key")
		stgCertPath := filepath.Join(stagingDir, "tls.crt")
		stgKeyPath := filepath.Join(stagingDir, "tls.key")

		// 1. Initial 2-day cert (serial 777)
		initCertPEM, initKeyPEM := generateTestCertAndKey(t, 2*24*time.Hour, 777)
		_ = os.WriteFile(actCertPath, initCertPEM, 0644)
		_ = os.WriteFile(actKeyPath, initKeyPEM, 0600)

		// 2. Replacement 365-day cert (serial 888)
		newCertPEM, newKeyPEM := generateTestCertAndKey(t, 365*24*time.Hour, 888)
		_ = os.WriteFile(stgCertPath, newCertPEM, 0644)
		_ = os.WriteFile(stgKeyPath, newKeyPEM, 0600)

		// TLS server with dynamic certificate reloading
		var certMu sync.RWMutex
		activePair, err := tls.X509KeyPair(initCertPEM, initKeyPEM)
		if err != nil {
			t.Fatalf("failed parsing initial keypair: %v", err)
		}

		tlsConf := &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				certMu.RLock()
				defer certMu.RUnlock()
				return &activePair, nil
			},
		}

		tlsListener, err := tls.Listen("tcp", tlsAddr, tlsConf)
		if err != nil {
			t.Fatalf("failed starting TLS listener: %v", err)
		}
		defer tlsListener.Close()

		tlsMux := http.NewServeMux()
		tlsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		tlsServer := &http.Server{Handler: tlsMux}
		go func() {
			_ = tlsServer.Serve(tlsListener)
		}()
		defer tlsServer.Close()

		reloadFn := func() error {
			certMu.Lock()
			defer certMu.Unlock()
			newPair, err := tls.LoadX509KeyPair(actCertPath, actKeyPath)
			if err != nil {
				return err
			}
			activePair = newPair
			return nil
		}

		rb := runbooks.NewTLSCertRotationRunbook(runbooks.TLSRotationConfig{
			ServiceName:      "ai-security-guardrail-proxy",
			StagedCertPath:   stgCertPath,
			StagedKeyPath:    stgKeyPath,
			ActiveCertPath:   actCertPath,
			ActiveKeyPath:    actKeyPath,
			BackupDir:        filepath.Join(tmpDir, "tls-backup"),
			TargetAddr:       tlsAddr,
			HealthURL:        fmt.Sprintf("https://%s/healthz", tlsAddr),
			ReloadFn:         reloadFn,
			ExecutionTimeout: 5 * time.Second,
		})
		_ = eng.RegisterRunbook(rb)

		res, err := eng.RunDirect(context.Background(), rb.ID, "ai-security-guardrail-proxy")
		if err != nil {
			t.Fatalf("TLS rotation failed: %v", err)
		}
		if res.FinalState != model.StateCommitted {
			t.Fatalf("expected state COMMITTED, got %s", res.FinalState)
		}

		// Verify TLS handshake presents new certificate with serial 888 (hex 378)
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		tlsConn, err := tls.DialWithDialer(dialer, "tcp", tlsAddr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("TLS dial failed: %v", err)
		}
		defer tlsConn.Close()

		presented := tlsConn.ConnectionState().PeerCertificates[0]
		if presented.SerialNumber.Cmp(big.NewInt(888)) != 0 {
			t.Errorf("expected serial 888, got %s", presented.SerialNumber.Text(10))
		}
	})

	// -------------------------------------------------------------------------
	// Verification 7: Runbook 4 - Configuration Rollback to LKG
	// -------------------------------------------------------------------------
	t.Run("Runbook_ConfigRollback", func(t *testing.T) {
		engCfg := engine.EngineConfig{
			LockDir:          filepath.Join(tmpDir, "locks-rb4"),
			AuditLogPath:     filepath.Join(tmpDir, "audit-rb4.wal"),
			JournalDir:       filepath.Join(tmpDir, "journal-rb4"),
			DampingStatePath: filepath.Join(tmpDir, "damping-rb4.json"),
			HostUUID:         "e2e-rb4-node",
		}
		eng, err := engine.NewEngine(engCfg)
		if err != nil {
			t.Fatalf("failed creating engine: %v", err)
		}
		defer eng.Close()

		activeCfgPath := filepath.Join(configDir, "config.yaml")
		lkgCfgPath := filepath.Join(lkgDir, "ai-gateway.config.yaml")

		lkgContent := "server:\n  host: 127.0.0.1\n  port: 8080\n"
		_ = os.WriteFile(lkgCfgPath, []byte(lkgContent), 0644)
		lkgHash := sha256.Sum256([]byte(lkgContent))

		// Write corrupted config
		corruptContent := "server:\n  host: [unterminated\n"
		_ = os.WriteFile(activeCfgPath, []byte(corruptContent), 0644)

		rb := runbooks.NewConfigRollbackRunbook(runbooks.ConfigRollbackConfig{
			ServiceName:      "ai-gateway",
			ActiveConfigPath: activeCfgPath,
			LKGConfigPath:    lkgCfgPath,
			QuarantineDir:    filepath.Join(tmpDir, "quarantine"),
			HealthURL:        "",
			ExecutionTimeout: 5 * time.Second,
		})
		_ = eng.RegisterRunbook(rb)

		res, err := eng.RunDirect(context.Background(), rb.ID, "ai-gateway")
		if err != nil {
			t.Fatalf("config rollback failed: %v", err)
		}
		if res.FinalState != model.StateCommitted {
			t.Fatalf("expected state COMMITTED, got %s", res.FinalState)
		}

		// Verify active config matches LKG hash
		curData, _ := os.ReadFile(activeCfgPath)
		curHash := sha256.Sum256(curData)
		if !bytes.Equal(curHash[:], lkgHash[:]) {
			t.Errorf("active config hash does not match LKG after rollback")
		}
	})

	// -------------------------------------------------------------------------
	// Verification 8: Graceful Daemon Shutdown & Ledger Integrity Verification
	// -------------------------------------------------------------------------
	t.Run("Daemon_Shutdown_And_Ledger_Integrity", func(t *testing.T) {
		// Send SIGTERM to the running daemon process
		if err := daemonCmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("failed to send SIGTERM to daemon: %v\nDaemon output:\n%s", err, daemonStdout.String())
		}

		select {
		case <-daemonExited:
			// Process exited cleanly
		case <-time.After(5 * time.Second):
			t.Fatal("daemon did not exit within 5s of SIGTERM")
		}

		// Verify Unix domain socket file was unlinked
		if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
			t.Errorf("expected socket file %s to be unlinked after shutdown", sockPath)
		}

		// Assert cryptographic audit ledger integrity
		report, err := audit.VerifyLedgerFile(auditLog)
		if err != nil {
			t.Fatalf("audit ledger verification returned error: %v", err)
		}
		if !report.Valid {
			t.Errorf("audit ledger hash chain verification failed")
		}
		if report.TotalRecords < 2 {
			t.Errorf("expected at least 2 audit entries, found %d", report.TotalRecords)
		}
		if report.GenesisHash == "" || report.TailHash == "" {
			t.Errorf("missing genesis or tail hash in audit report")
		}
	})
}
