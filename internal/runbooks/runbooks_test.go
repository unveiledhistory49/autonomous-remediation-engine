package runbooks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"autonomous-remediation-engine/internal/engine"
	"autonomous-remediation-engine/internal/model"
)

func generateTestCertAndKey(t *testing.T, validDuration time.Duration, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			Organization: []string{"Acme Test"},
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
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

func setupEngineForRunbook(t *testing.T, tempDir string) *engine.Engine {
	t.Helper()
	cfg := engine.EngineConfig{
		LockDir:      filepath.Join(tempDir, "locks"),
		AuditLogPath: filepath.Join(tempDir, "audit.log"),
		JournalDir:   filepath.Join(tempDir, "journal"),
		HostUUID:     "test-node-arm64",
	}

	eng, err := engine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	return eng
}

// -----------------------------------------------------------------------------
// Test 1: RBK-DISK-001 (disk_cleanup_var_log)
// -----------------------------------------------------------------------------
func TestRunbook_DiskCleanup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rbk-disk-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	eng := setupEngineForRunbook(t, tempDir)
	defer eng.Close()

	logDir := filepath.Join(tempDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		t.Fatalf("failed to create logs dir: %v", err)
	}

	// 1. Create active log file
	activeLogPath := filepath.Join(logDir, "ai-gateway.log")
	activeContent := "2026-09-22 active log stream entry\n"
	if err := os.WriteFile(activeLogPath, []byte(activeContent), 0644); err != nil {
		t.Fatalf("failed to write active log: %v", err)
	}

	var activeStat syscall.Stat_t
	if err := syscall.Stat(activeLogPath, &activeStat); err != nil {
		t.Fatalf("failed to stat active log: %v", err)
	}
	activeInode := activeStat.Ino

	// 2. Create 5 expired archives with varying modification times
	archiveFiles := []struct {
		name    string
		age     time.Duration
		payload []byte
	}{
		{"ai-gateway.log.2026-09-10.gz", 5 * 24 * time.Hour, []byte("archive 1")},
		{"ai-gateway.log.2026-09-11.gz", 4 * 24 * time.Hour, []byte("archive 2")},
		{"ai-gateway.log.2026-09-12.old", 3 * 24 * time.Hour, []byte("archive 3")},
		{"ai-gateway.log.2026-09-13.gz", 2 * 24 * time.Hour, []byte("archive 4")},
		{"ai-gateway.log.1", 1 * 24 * time.Hour, []byte("archive 5")},
	}

	for _, af := range archiveFiles {
		p := filepath.Join(logDir, af.name)
		if err := os.WriteFile(p, af.payload, 0644); err != nil {
			t.Fatalf("failed to write archive: %v", err)
		}
		pastTime := time.Now().Add(-af.age)
		_ = os.Chtimes(p, pastTime, pastTime)
	}

	// 3. Configure and register RBK-DISK-001
	cfg := DiskCleanupConfig{
		TargetDir:          logDir,
		ActiveLogName:      "ai-gateway.log",
		MinFreePctRequired: 0.0, // test filesystem free space
		MaxFilesToDelete:   10,
		MaxBytesToDelete:   524288000,
		ExecutionTimeout:   5 * time.Second,
	}

	rb := NewDiskCleanupRunbook(cfg)
	if err := eng.RegisterRunbook(rb); err != nil {
		t.Fatalf("failed to register runbook: %v", err)
	}

	// 4. Execute runbook
	ctx := context.Background()
	res, err := eng.RunDirect(ctx, IDDiskCleanupVarLog, logDir)
	if err != nil {
		t.Fatalf("runbook execution failed: %v", err)
	}

	if !res.Success || res.FinalState != model.StateCommitted {
		t.Fatalf("expected COMMITTED, got %s (err: %s)", res.FinalState, res.Error)
	}

	if res.ExecutionRes == nil || res.ExecutionRes.BytesMutated <= 0 {
		t.Fatalf("expected positive BytesMutated, got: %+v", res.ExecutionRes)
	}

	// 5. Verify postconditions:
	// - Active log file must exist, be regular, and have identical inode and content
	fi, err := os.Stat(activeLogPath)
	if err != nil {
		t.Fatalf("active log file was deleted!")
	}
	if sysStat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if sysStat.Ino != activeInode {
			t.Fatalf("active log inode modified! expected %d, got %d", activeInode, sysStat.Ino)
		}
	}
	data, _ := os.ReadFile(activeLogPath)
	if string(data) != activeContent {
		t.Fatalf("active log content was corrupted!")
	}

	// - All 5 expired archives should be deleted
	for _, af := range archiveFiles {
		p := filepath.Join(logDir, af.name)
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("expired archive %s was not pruned", af.name)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 2: RBK-PROC-001 (service_hang_recovery)
// -----------------------------------------------------------------------------
func TestRunbook_ServiceHangRecovery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rbk-proc-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	eng := setupEngineForRunbook(t, tempDir)
	defer eng.Close()

	// Choose a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	healthURL := fmt.Sprintf("http://%s/healthz", addr)

	// Mock replacement process server
	var healthyServer *http.Server
	spawnFn := func() (int, error) {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})
		healthyServer = &http.Server{
			Addr:    addr,
			Handler: mux,
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return 0, err
		}
		go func() {
			_ = healthyServer.Serve(l)
		}()
		// Return current PID as the replacement PID
		return os.Getpid(), nil
	}
	defer func() {
		if healthyServer != nil {
			_ = healthyServer.Close()
		}
	}()

	cfg := ServiceHangConfig{
		ServiceName:      "ai-gateway",
		Port:             port,
		HealthURL:        healthURL,
		TargetPID:        0, // simulates hang where health is failing
		SpawnFn:          spawnFn,
		TermTimeout:      1 * time.Second,
		KillTimeout:      1 * time.Second,
		ExecutionTimeout: 5 * time.Second,
	}

	rb := NewServiceHangRecoveryRunbook(cfg)
	if err := eng.RegisterRunbook(rb); err != nil {
		t.Fatalf("failed to register runbook: %v", err)
	}

	ctx := context.Background()
	res, err := eng.RunDirect(ctx, IDServiceHangRecovery, "ai-gateway")
	if err != nil {
		t.Fatalf("service hang recovery runbook failed: %v", err)
	}

	if !res.Success || res.FinalState != model.StateCommitted {
		t.Fatalf("expected COMMITTED, got %s (err: %s)", res.FinalState, res.Error)
	}

	// Verify health check returns 200 OK
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		t.Fatalf("failed to probe recovered service: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// Test 3: RBK-TLS-001 (tls_cert_rotation)
// -----------------------------------------------------------------------------
func TestRunbook_TLSCertRotation(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rbk-tls-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	eng := setupEngineForRunbook(t, tempDir)
	defer eng.Close()

	activeCertPath := filepath.Join(tempDir, "active.crt")
	activeKeyPath := filepath.Join(tempDir, "active.key")
	stagedCertPath := filepath.Join(tempDir, "staged.crt")
	stagedKeyPath := filepath.Join(tempDir, "staged.key")
	backupDir := filepath.Join(tempDir, "backup")

	// 1. Generate active cert with 5-day validity and serial 1001
	actCertBytes, actKeyBytes := generateTestCertAndKey(t, 5*24*time.Hour, 1001)
	if err := os.WriteFile(activeCertPath, actCertBytes, 0644); err != nil {
		t.Fatalf("failed to write active cert: %v", err)
	}
	if err := os.WriteFile(activeKeyPath, actKeyBytes, 0600); err != nil {
		t.Fatalf("failed to write active key: %v", err)
	}

	// 2. Generate staged cert with 365-day validity (> 30 days) and serial 2002
	stagedCertBytes, stagedKeyBytes := generateTestCertAndKey(t, 365*24*time.Hour, 2002)
	if err := os.WriteFile(stagedCertPath, stagedCertBytes, 0644); err != nil {
		t.Fatalf("failed to write staged cert: %v", err)
	}
	if err := os.WriteFile(stagedKeyPath, stagedKeyBytes, 0600); err != nil {
		t.Fatalf("failed to write staged key: %v", err)
	}

	// 3. Start TLS loopback server with dynamic certificate loading
	var activeTLSCert tls.Certificate
	var certMu sync.RWMutex
	pair, err := tls.X509KeyPair(actCertBytes, actKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse initial TLS keypair: %v", err)
	}
	activeTLSCert = pair

	tlsConf := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certMu.RLock()
			defer certMu.RUnlock()
			return &activeTLSCert, nil
		},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	healthURL := fmt.Sprintf("https://%s/healthz", serverAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("HEALTHY"))
	})
	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	// Reload hook when SIGHUP / reload is triggered
	reloadFn := func() error {
		certMu.Lock()
		defer certMu.Unlock()
		newPair, err := tls.LoadX509KeyPair(activeCertPath, activeKeyPath)
		if err != nil {
			return err
		}
		activeTLSCert = newPair
		return nil
	}

	// 4. Configure RBK-TLS-001
	cfg := TLSRotationConfig{
		ServiceName:      "ai-security-guardrail-proxy",
		StagedCertPath:   stagedCertPath,
		StagedKeyPath:    stagedKeyPath,
		ActiveCertPath:   activeCertPath,
		ActiveKeyPath:    activeKeyPath,
		BackupDir:        backupDir,
		TargetAddr:       serverAddr,
		HealthURL:        healthURL,
		ReloadFn:         reloadFn,
		ExecutionTimeout: 5 * time.Second,
	}

	rb := NewTLSCertRotationRunbook(cfg)
	if err := eng.RegisterRunbook(rb); err != nil {
		t.Fatalf("failed to register runbook: %v", err)
	}

	// 5. Execute runbook
	ctx := context.Background()
	res, err := eng.RunDirect(ctx, IDTLSCertRotation, "ai-security-guardrail-proxy")
	if err != nil {
		t.Fatalf("TLS cert rotation runbook failed: %v", err)
	}

	if !res.Success || res.FinalState != model.StateCommitted {
		t.Fatalf("expected COMMITTED, got %s (err: %s)", res.FinalState, res.Error)
	}

	// 6. Direct client TLS probe: verify serial number is 2002 (hex: 7d2)
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("client TLS dial failed: %v", err)
	}
	defer conn.Close()

	presentedCert := conn.ConnectionState().PeerCertificates[0]
	if presentedCert.SerialNumber.Cmp(big.NewInt(2002)) != 0 {
		t.Fatalf("expected presented cert serial 2002, got: %s", presentedCert.SerialNumber.Text(10))
	}
}

// -----------------------------------------------------------------------------
// Test 4: RBK-CFG-001 (config_rollback)
// -----------------------------------------------------------------------------
func TestRunbook_ConfigRollback(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rbk-cfg-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	eng := setupEngineForRunbook(t, tempDir)
	defer eng.Close()

	activeConfigPath := filepath.Join(tempDir, "config.yaml")
	lkgConfigPath := filepath.Join(tempDir, "config.yaml.lkg")
	quarantineDir := filepath.Join(tempDir, "quarantine")

	// 1. Valid LKG config
	lkgContent := `server:
  host: 127.0.0.1
  port: 8080
logging:
  level: info
`
	if err := os.WriteFile(lkgConfigPath, []byte(lkgContent), 0644); err != nil {
		t.Fatalf("failed to write LKG config: %v", err)
	}

	// 2. Corrupted active config (e.g. invalid syntax or wrong port)
	corruptContent := `server:
  host: 0.0.0.0
  corrupted_syntax: "unclosed string
`
	if err := os.WriteFile(activeConfigPath, []byte(corruptContent), 0644); err != nil {
		t.Fatalf("failed to write corrupt config: %v", err)
	}

	// Choose a free port for mock health server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	healthURL := fmt.Sprintf("http://%s/healthz", addr)

	// Mock service that verifies config before serving healthz
	var server *http.Server
	restartFn := func() error {
		if server != nil {
			_ = server.Close()
		}
		// Read active config to verify it restored properly
		curData, err := os.ReadFile(activeConfigPath)
		if err != nil {
			return err
		}
		if err := ValidateConfigSyntax(curData); err != nil {
			return fmt.Errorf("config syntax invalid: %w", err)
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("LKG_RESTORED"))
		})

		server = &http.Server{Addr: addr, Handler: mux}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go func() {
			_ = server.Serve(l)
		}()
		return nil
	}
	defer func() {
		if server != nil {
			_ = server.Close()
		}
	}()

	cfg := ConfigRollbackConfig{
		ServiceName:      "ai-gateway",
		ActiveConfigPath: activeConfigPath,
		LKGConfigPath:    lkgConfigPath,
		QuarantineDir:    quarantineDir,
		HealthURL:        healthURL,
		RestartFn:        restartFn,
		ExecutionTimeout: 5 * time.Second,
	}

	rb := NewConfigRollbackRunbook(cfg)
	if err := eng.RegisterRunbook(rb); err != nil {
		t.Fatalf("failed to register runbook: %v", err)
	}

	ctx := context.Background()
	res, err := eng.RunDirect(ctx, IDConfigRollback, "ai-gateway")
	if err != nil {
		t.Fatalf("config rollback runbook failed: %v", err)
	}

	if !res.Success || res.FinalState != model.StateCommitted {
		t.Fatalf("expected COMMITTED, got %s (err: %s)", res.FinalState, res.Error)
	}

	// Verify active config matches LKG exactly
	activeData, _ := os.ReadFile(activeConfigPath)
	if string(activeData) != lkgContent {
		t.Fatalf("restored config does not match LKG content!")
	}

	// Verify quarantine directory contains the corrupted file
	entries, err := os.ReadDir(quarantineDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("quarantine directory does not contain quarantined file")
	}

	// Verify health check returns 200 OK
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		t.Fatalf("health probe failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
}

// -----------------------------------------------------------------------------
// Test 5: Invariant & Precondition Edge Cases
// -----------------------------------------------------------------------------
func TestRunbook_PreconditionEdgeCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rbk-edge-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Modulus verification failure between cert and mismatched key
	certPEM, _ := generateTestCertAndKey(t, 365*24*time.Hour, 5001)
	_, otherKeyPEM := generateTestCertAndKey(t, 365*24*time.Hour, 5002)

	_, err = VerifyCertAndKeyModulus(certPEM, otherKeyPEM)
	if err == nil {
		t.Fatalf("expected modulus mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected mismatch in error, got: %v", err)
	}

	// 2. Expired certificate validity check (< 30 days)
	shortCertPEM, shortKeyPEM := generateTestCertAndKey(t, 10*24*time.Hour, 5003)
	cert, err := VerifyCertAndKeyModulus(shortCertPEM, shortKeyPEM)
	if err != nil {
		t.Fatalf("modulus verification should pass for matching pair: %v", err)
	}
	if time.Until(cert.NotAfter) > 30*24*time.Hour {
		t.Fatalf("expected validity < 30 days")
	}

	// 3. ValidateConfigSyntax with tab indentation error
	invalidYAML := []byte("server:\n\tport: 8080\n")
	if err := ValidateConfigSyntax(invalidYAML); err == nil {
		t.Fatalf("expected YAML syntax error for tab characters, got nil")
	}

	// 4. Default Catalog contains all 4 runbooks
	cat := DefaultCatalog()
	if len(cat) != 4 {
		t.Fatalf("expected 4 default runbooks, got %d", len(cat))
	}
	expectedIDs := map[string]bool{
		IDDiskCleanupVarLog:   false,
		IDServiceHangRecovery: false,
		IDTLSCertRotation:     false,
		IDConfigRollback:      false,
	}
	for _, rb := range cat {
		expectedIDs[rb.ID] = true
	}
	for id, found := range expectedIDs {
		if !found {
			t.Fatalf("default catalog missing runbook ID %s", id)
		}
	}
}
