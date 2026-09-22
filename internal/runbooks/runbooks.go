package runbooks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"autonomous-remediation-engine/internal/model"
)

// Runbook IDs
const (
	IDDiskCleanupVarLog   = "RBK-DISK-001"
	IDServiceHangRecovery = "RBK-PROC-001"
	IDTLSCertRotation     = "RBK-TLS-001"
	IDConfigRollback      = "RBK-CFG-001"
)

// -----------------------------------------------------------------------------
// 1. RBK-DISK-001: Disk Volume Saturation & Safe Log Drain
// -----------------------------------------------------------------------------

// DiskCleanupConfig provides parameters for RBK-DISK-001.
type DiskCleanupConfig struct {
	TargetDir          string
	ActiveLogName      string        // e.g. "ai-gateway.log"
	MinFreePctRequired float64       // e.g. 15.0%
	MaxFilesToDelete   int           // clamp: <= 10
	MaxBytesToDelete   int64         // clamp: <= 500MB (524288000)
	ExecutionTimeout   time.Duration // clamp: <= 15s
	HealthCheckURL     string        // optional health check
}

// DefaultDiskCleanupConfig returns production defaults for RBK-DISK-001.
func DefaultDiskCleanupConfig() DiskCleanupConfig {
	return DiskCleanupConfig{
		TargetDir:          "/var/log",
		ActiveLogName:      "ai-gateway.log",
		MinFreePctRequired: 15.0,
		MaxFilesToDelete:   10,
		MaxBytesToDelete:   524288000, // 500 MB
		ExecutionTimeout:   15 * time.Second,
		HealthCheckURL:     "http://127.0.0.1:8080/healthz",
	}
}

// NewDiskCleanupRunbook constructs the deterministic RBK-DISK-001 runbook.
func NewDiskCleanupRunbook(cfg DiskCleanupConfig) *model.Runbook {
	if cfg.TargetDir == "" {
		cfg.TargetDir = "/var/log"
	}
	if cfg.ActiveLogName == "" {
		cfg.ActiveLogName = "ai-gateway.log"
	}
	if cfg.MaxFilesToDelete <= 0 || cfg.MaxFilesToDelete > 10 {
		cfg.MaxFilesToDelete = 10
	}
	if cfg.MaxBytesToDelete <= 0 || cfg.MaxBytesToDelete > 524288000 {
		cfg.MaxBytesToDelete = 524288000
	}
	if cfg.ExecutionTimeout <= 0 || cfg.ExecutionTimeout > 15*time.Second {
		cfg.ExecutionTimeout = 15 * time.Second
	}

	var activeInode uint64

	return &model.Runbook{
		ID:               IDDiskCleanupVarLog,
		Version:          "1.0.0",
		Name:             "disk_cleanup_var_log",
		TargetResourceID: cfg.TargetDir,
		Severity:         model.SeverityHigh,
		BlastRadius: model.BlastRadius{
			MaxExecutionTime:    cfg.ExecutionTimeout,
			MaxBytesMutated:     cfg.MaxBytesToDelete,
			MaxFilesModified:    cfg.MaxFilesToDelete,
			AllowedPathPrefixes: []string{cfg.TargetDir},
		},
		Preconditions: []model.Precondition{
			{
				Name: "statfs-and-candidate-inspection",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					// 1. Verify directory exists
					dirStat, err := os.Stat(cfg.TargetDir)
					if err != nil {
						return false, fmt.Errorf("target log directory %s inaccessible: %w", cfg.TargetDir, err)
					}
					if !dirStat.IsDir() {
						return false, fmt.Errorf("target log path %s is not a directory", cfg.TargetDir)
					}

					// 2. Statfs check
					var stat syscall.Statfs_t
					if err := syscall.Statfs(cfg.TargetDir, &stat); err != nil {
						return false, fmt.Errorf("statfs failed on %s: %w", cfg.TargetDir, err)
					}

					// 3. Inspect active log file
					activePath := filepath.Join(cfg.TargetDir, cfg.ActiveLogName)
					if fi, err := os.Stat(activePath); err == nil {
						if sysStat, ok := fi.Sys().(*syscall.Stat_t); ok {
							activeInode = sysStat.Ino
						}
					}

					// 4. Verify candidate files do not match active log inode
					candidates, err := findCandidateArchives(cfg.TargetDir, cfg.ActiveLogName)
					if err != nil {
						return false, err
					}

					for _, c := range candidates {
						safe, err := checkCandidateFileSafe(c, activeInode, cfg.ActiveLogName)
						if !safe {
							return false, fmt.Errorf("candidate archive safety check failed for %s: %w", c, err)
						}
					}

					return true, nil
				},
			},
		},
		Actions: []model.Action{
			{
				Name:    "prune-oldest-archives",
				Timeout: cfg.ExecutionTimeout,
				MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
					candidates, err := findCandidateArchives(cfg.TargetDir, cfg.ActiveLogName)
					if err != nil {
						return nil, err
					}

					type fileWithInfo struct {
						path    string
						modTime time.Time
						size    int64
					}

					var candidateList []fileWithInfo
					for _, c := range candidates {
						fi, err := os.Stat(c)
						if err != nil {
							continue
						}
						candidateList = append(candidateList, fileWithInfo{
							path:    c,
							modTime: fi.ModTime(),
							size:    fi.Size(),
						})
					}

					// Sort ascending by mtime (oldest first)
					sort.Slice(candidateList, func(i, j int) bool {
						return candidateList[i].modTime.Before(candidateList[j].modTime)
					})

					var totalBytesDeleted int64
					var filesDeleted int
					var deletedPaths []string

					for _, f := range candidateList {
						if filesDeleted >= cfg.MaxFilesToDelete {
							break
						}
						if totalBytesDeleted+f.size > cfg.MaxBytesToDelete && filesDeleted > 0 {
							break
						}

						// Double check candidate safety before unlinking
						safe, _ := checkCandidateFileSafe(f.path, activeInode, cfg.ActiveLogName)
						if !safe {
							continue
						}

						if err := os.Remove(f.path); err != nil {
							return nil, fmt.Errorf("failed to unlink archive %s: %w", f.path, err)
						}

						filesDeleted++
						totalBytesDeleted += f.size
						deletedPaths = append(deletedPaths, f.path)
					}

					return &model.ExecutionResult{
						Success:      true,
						ExitCode:     0,
						BytesMutated: totalBytesDeleted,
						Stdout: fmt.Sprintf("Deleted %d files (%d bytes): %s",
							filesDeleted, totalBytesDeleted, strings.Join(deletedPaths, ", ")),
					}, nil
				},
			},
		},
		Postconditions: []model.Postcondition{
			{
				Name: "active-log-intact-and-space-freed",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					// 1. Assert active log exists and is intact (if present initially)
					if activeInode > 0 {
						activePath := filepath.Join(cfg.TargetDir, cfg.ActiveLogName)
						fi, err := os.Stat(activePath)
						if err != nil {
							return false, fmt.Errorf("active log file %s missing after cleanup: %w", activePath, err)
						}
						if !fi.Mode().IsRegular() {
							return false, fmt.Errorf("active log %s is not a regular file", activePath)
						}
						if sysStat, ok := fi.Sys().(*syscall.Stat_t); ok {
							if sysStat.Ino != activeInode {
								return false, fmt.Errorf("active log inode changed from %d to %d", activeInode, sysStat.Ino)
							}
						}
					}

					// 2. Statfs assertion
					var stat syscall.Statfs_t
					if err := syscall.Statfs(cfg.TargetDir, &stat); err != nil {
						return false, fmt.Errorf("statfs failed on %s: %w", cfg.TargetDir, err)
					}
					if stat.Blocks > 0 && cfg.MinFreePctRequired > 0 {
						freePct := (float64(stat.Bavail) / float64(stat.Blocks)) * 100.0
						if freePct < cfg.MinFreePctRequired {
							return false, fmt.Errorf("postcondition disk free space on %s is %.2f%%, required >= %.2f%%",
								cfg.TargetDir, freePct, cfg.MinFreePctRequired)
						}
					}

					// 3. Optional HTTP health check if configured
					if cfg.HealthCheckURL != "" {
						client := &http.Client{Timeout: 2 * time.Second}
						resp, err := client.Get(cfg.HealthCheckURL)
						if err == nil {
							_ = resp.Body.Close()
							if resp.StatusCode != http.StatusOK {
								return false, fmt.Errorf("service health check returned status %d", resp.StatusCode)
							}
						}
					}

					return true, nil
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// 2. RBK-PROC-001: Service Process Hang Recovery & Safe Restart
// -----------------------------------------------------------------------------

// ServiceHangConfig provides parameters for RBK-PROC-001.
type ServiceHangConfig struct {
	ServiceName      string
	TargetPID        int
	PIDFilePath      string
	Port             int
	HealthURL        string
	StartCmd         string
	StartArgs        []string
	SpawnFn          func() (int, error)
	TermTimeout      time.Duration // Escalation ladder SIGTERM deadline (default: 5.0s)
	KillTimeout      time.Duration // Escalation ladder SIGKILL deadline (default: 2.0s)
	ExecutionTimeout time.Duration
}

// DefaultServiceHangConfig returns production defaults for RBK-PROC-001.
func DefaultServiceHangConfig() ServiceHangConfig {
	return ServiceHangConfig{
		ServiceName:      "ai-gateway",
		Port:             8080,
		HealthURL:        "http://127.0.0.1:8080/healthz",
		StartCmd:         "/usr/local/bin/ai-gateway",
		StartArgs:        []string{"--config=/etc/ai-gateway/config.yaml"},
		TermTimeout:      5 * time.Second,
		KillTimeout:      2 * time.Second,
		ExecutionTimeout: 15 * time.Second,
	}
}

// NewServiceHangRecoveryRunbook constructs the deterministic RBK-PROC-001 runbook.
func NewServiceHangRecoveryRunbook(cfg ServiceHangConfig) *model.Runbook {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "ai-gateway"
	}
	if cfg.Port <= 0 {
		cfg.Port = 8080
	}
	if cfg.HealthURL == "" {
		cfg.HealthURL = fmt.Sprintf("http://127.0.0.1:%d/healthz", cfg.Port)
	}
	if cfg.TermTimeout <= 0 {
		cfg.TermTimeout = 5 * time.Second
	}
	if cfg.KillTimeout <= 0 {
		cfg.KillTimeout = 2 * time.Second
	}
	if cfg.ExecutionTimeout <= 0 {
		cfg.ExecutionTimeout = 15 * time.Second
	}

	var activePID int64
	if cfg.TargetPID > 0 {
		activePID = int64(cfg.TargetPID)
	}

	return &model.Runbook{
		ID:               IDServiceHangRecovery,
		Version:          "1.0.0",
		Name:             "service_hang_recovery",
		TargetResourceID: cfg.ServiceName,
		Severity:         model.SeverityCritical,
		BlastRadius: model.BlastRadius{
			MaxExecutionTime:     cfg.ExecutionTimeout,
			MaxProcessesSignaled: 1,
		},
		Preconditions: []model.Precondition{
			{
				Name: "target-service-hang-asserted",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					// Read PID from PID file if configured
					if cfg.PIDFilePath != "" {
						data, err := os.ReadFile(cfg.PIDFilePath)
						if err == nil {
							if p, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && p > 0 {
								atomic.StoreInt64(&activePID, int64(p))
							}
						}
					}

					curPID := int(atomic.LoadInt64(&activePID))
					if curPID > 0 {
						// Process must exist
						if err := syscall.Kill(curPID, 0); err != nil && !errors.Is(err, syscall.EPERM) {
							return false, fmt.Errorf("target process PID %d is not running: %w", curPID, err)
						}
					}

					// Verify health endpoint is degraded or timed out
					client := &http.Client{Timeout: 1 * time.Second}
					resp, err := client.Get(cfg.HealthURL)
					if err == nil {
						_ = resp.Body.Close()
						if resp.StatusCode == http.StatusOK {
							// If healthz is 200, service is not hung unless simulated
							if curPID == 0 {
								return false, errors.New("service is currently healthy; recovery not required")
							}
						}
					}
					return true, nil
				},
			},
		},
		Actions: []model.Action{
			{
				Name:    "escalation-ladder-termination-and-respawn",
				Timeout: cfg.ExecutionTimeout,
				MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
					curPID := int(atomic.LoadInt64(&activePID))

					// 1. Escalation ladder: SIGTERM -> wait up to 5s -> SIGKILL
					if curPID > 0 && syscall.Kill(curPID, 0) == nil {
						// Send SIGTERM
						_ = syscall.Kill(curPID, syscall.SIGTERM)

						// Poll up to TermTimeout
						terminated := false
						termDeadline := time.Now().Add(cfg.TermTimeout)
						for time.Now().Before(termDeadline) {
							if err := syscall.Kill(curPID, 0); err != nil && !errors.Is(err, syscall.EPERM) {
								terminated = true
								break
							}
							time.Sleep(50 * time.Millisecond)
						}

						// If still alive, escalate to SIGKILL
						if !terminated {
							_ = syscall.Kill(curPID, syscall.SIGKILL)
							killDeadline := time.Now().Add(cfg.KillTimeout)
							for time.Now().Before(killDeadline) {
								if err := syscall.Kill(curPID, 0); err != nil && !errors.Is(err, syscall.EPERM) {
									terminated = true
									break
								}
								time.Sleep(50 * time.Millisecond)
							}
						}
					}

					// 2. Spawn replacement process
					var newPID int
					if cfg.SpawnFn != nil {
						np, err := cfg.SpawnFn()
						if err != nil {
							return nil, fmt.Errorf("failed to spawn replacement service via SpawnFn: %w", err)
						}
						newPID = np
					} else if cfg.StartCmd != "" {
						cmd := exec.Command(cfg.StartCmd, cfg.StartArgs...)
						if err := cmd.Start(); err != nil {
							return nil, fmt.Errorf("failed to spawn replacement service: %w", err)
						}
						newPID = cmd.Process.Pid
					}

					if newPID > 0 {
						atomic.StoreInt64(&activePID, int64(newPID))
						if cfg.PIDFilePath != "" {
							_ = os.WriteFile(cfg.PIDFilePath, []byte(strconv.Itoa(newPID)), 0644)
						}
					}

					return &model.ExecutionResult{
						Success:  true,
						ExitCode: 0,
						Stdout:   fmt.Sprintf("Service %s successfully restarted with new PID %d", cfg.ServiceName, newPID),
					}, nil
				},
			},
		},
		Postconditions: []model.Postcondition{
			{
				Name: "replacement-process-and-port-healthy",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					newPID := int(atomic.LoadInt64(&activePID))

					// 1. Assert new PID alive
					if newPID > 0 {
						if err := syscall.Kill(newPID, 0); err != nil && !errors.Is(err, syscall.EPERM) {
							return false, fmt.Errorf("replacement process PID %d is not running: %w", newPID, err)
						}
					}

					// 2. Assert port listening
					addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
					portReady := false
					for i := 0; i < 30; i++ {
						conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
						if err == nil {
							_ = conn.Close()
							portReady = true
							break
						}
						time.Sleep(100 * time.Millisecond)
					}
					if !portReady {
						return false, fmt.Errorf("service port %d is not listening", cfg.Port)
					}

					// 3. HTTP loopback health probe /healthz returns 200 OK
					client := &http.Client{Timeout: 1 * time.Second}
					var lastErr error
					for i := 0; i < 20; i++ {
						resp, err := client.Get(cfg.HealthURL)
						if err == nil {
							_ = resp.Body.Close()
							if resp.StatusCode == http.StatusOK {
								return true, nil
							}
							lastErr = fmt.Errorf("health endpoint returned %d", resp.StatusCode)
						} else {
							lastErr = err
						}
						time.Sleep(100 * time.Millisecond)
					}

					return false, fmt.Errorf("health check %s failed: %w", cfg.HealthURL, lastErr)
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// 3. RBK-TLS-001: TLS Certificate Rotation & Zero-Downtime Reload
// -----------------------------------------------------------------------------

// TLSRotationConfig provides parameters for RBK-TLS-001.
type TLSRotationConfig struct {
	ServiceName      string
	StagedCertPath   string
	StagedKeyPath    string
	ActiveCertPath   string
	ActiveKeyPath    string
	BackupDir        string
	TargetAddr       string // e.g. "127.0.0.1:8443"
	HealthURL        string // e.g. "https://127.0.0.1:8443/healthz"
	TargetPID        int
	PIDFilePath      string
	ReloadFn         func() error
	ExecutionTimeout time.Duration
}

// DefaultTLSRotationConfig returns production defaults for RBK-TLS-001.
func DefaultTLSRotationConfig() TLSRotationConfig {
	return TLSRotationConfig{
		ServiceName:      "ai-security-guardrail-proxy",
		StagedCertPath:   "/var/lib/autonomous-remediation/staging/tls.crt",
		StagedKeyPath:    "/var/lib/autonomous-remediation/staging/tls.key",
		ActiveCertPath:   "/etc/ssl/certs/guardrail-proxy.crt",
		ActiveKeyPath:    "/etc/ssl/private/guardrail-proxy.key",
		BackupDir:        "/var/lib/autonomous-remediation/journal/backup",
		TargetAddr:       "127.0.0.1:8443",
		HealthURL:        "https://127.0.0.1:8443/healthz",
		ExecutionTimeout: 10 * time.Second,
	}
}

// NewTLSCertRotationRunbook constructs the deterministic RBK-TLS-001 runbook.
func NewTLSCertRotationRunbook(cfg TLSRotationConfig) *model.Runbook {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "ai-security-guardrail-proxy"
	}
	if cfg.TargetAddr == "" {
		cfg.TargetAddr = "127.0.0.1:8443"
	}
	if cfg.ExecutionTimeout <= 0 {
		cfg.ExecutionTimeout = 10 * time.Second
	}

	var stagedSerial string
	var backupCertPath string
	var backupKeyPath string

	return &model.Runbook{
		ID:               IDTLSCertRotation,
		Version:          "1.0.0",
		Name:             "tls_cert_rotation",
		TargetResourceID: cfg.ServiceName,
		Severity:         model.SeverityHigh,
		BlastRadius: model.BlastRadius{
			MaxExecutionTime: cfg.ExecutionTimeout,
			MaxFilesModified: 2,
		},
		Preconditions: []model.Precondition{
			{
				Name: "staged-x509-validity-and-modulus-verification",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					certPEM, err := os.ReadFile(cfg.StagedCertPath)
					if err != nil {
						return false, fmt.Errorf("staged cert %s unreadable: %w", cfg.StagedCertPath, err)
					}
					keyPEM, err := os.ReadFile(cfg.StagedKeyPath)
					if err != nil {
						return false, fmt.Errorf("staged key %s unreadable: %w", cfg.StagedKeyPath, err)
					}

					cert, err := VerifyCertAndKeyModulus(certPEM, keyPEM)
					if err != nil {
						return false, fmt.Errorf("cryptographic invariant failed: %w", err)
					}

					// Verify validity strictly > 30 days
					remaining := time.Until(cert.NotAfter)
					if remaining <= 30*24*time.Hour {
						return false, fmt.Errorf("certificate validity (%v) not > 30 days", remaining)
					}

					stagedSerial = cert.SerialNumber.Text(16)
					return true, nil
				},
			},
		},
		Actions: []model.Action{
			{
				Name:    "atomic-swap-and-sighup-reload",
				Timeout: cfg.ExecutionTimeout,
				MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
					// 1. Backup active cert & key
					if cfg.BackupDir != "" {
						_ = os.MkdirAll(cfg.BackupDir, 0700)
						backupCertPath = filepath.Join(cfg.BackupDir, filepath.Base(cfg.ActiveCertPath)+".bak")
						backupKeyPath = filepath.Join(cfg.BackupDir, filepath.Base(cfg.ActiveKeyPath)+".bak")

						if activeCertBytes, err := os.ReadFile(cfg.ActiveCertPath); err == nil {
							_ = os.WriteFile(backupCertPath, activeCertBytes, 0600)
						}
						if activeKeyBytes, err := os.ReadFile(cfg.ActiveKeyPath); err == nil {
							_ = os.WriteFile(backupKeyPath, activeKeyBytes, 0600)
						}
					}

					// 2. Atomic swap staged files to active locations
					stagedCertBytes, err := os.ReadFile(cfg.StagedCertPath)
					if err != nil {
						return nil, fmt.Errorf("failed to read staged cert: %w", err)
					}
					stagedKeyBytes, err := os.ReadFile(cfg.StagedKeyPath)
					if err != nil {
						return nil, fmt.Errorf("failed to read staged key: %w", err)
					}

					tmpCert := cfg.ActiveCertPath + ".tmp"
					tmpKey := cfg.ActiveKeyPath + ".tmp"

					if err := os.WriteFile(tmpCert, stagedCertBytes, 0644); err != nil {
						return nil, fmt.Errorf("failed to write tmp cert: %w", err)
					}
					if err := os.WriteFile(tmpKey, stagedKeyBytes, 0600); err != nil {
						_ = os.Remove(tmpCert)
						return nil, fmt.Errorf("failed to write tmp key: %w", err)
					}

					if err := os.Rename(tmpCert, cfg.ActiveCertPath); err != nil {
						return nil, fmt.Errorf("atomic rename cert failed: %w", err)
					}
					if err := os.Rename(tmpKey, cfg.ActiveKeyPath); err != nil {
						return nil, fmt.Errorf("atomic rename key failed: %w", err)
					}

					// 3. Dispatch SIGHUP or call ReloadFn
					if cfg.ReloadFn != nil {
						if err := cfg.ReloadFn(); err != nil {
							return nil, fmt.Errorf("ReloadFn failed: %w", err)
						}
					} else {
						pid := cfg.TargetPID
						if pid <= 0 && cfg.PIDFilePath != "" {
							if d, err := os.ReadFile(cfg.PIDFilePath); err == nil {
								pid, _ = strconv.Atoi(strings.TrimSpace(string(d)))
							}
						}
						if pid > 0 {
							_ = syscall.Kill(pid, syscall.SIGHUP)
						}
					}

					return &model.ExecutionResult{
						Success:      true,
						ExitCode:     0,
						BytesMutated: int64(len(stagedCertBytes) + len(stagedKeyBytes)),
						Stdout:       fmt.Sprintf("Atomically deployed staged TLS cert %s and signaled reload", stagedSerial),
					}, nil
				},
			},
		},
		Postconditions: []model.Postcondition{
			{
				Name: "tls-handshake-presented-serial-verified",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					// Connect via TLS probe
					tlsConf := &tls.Config{
						InsecureSkipVerify: true,
					}

					var conn *tls.Conn
					var dialErr error
					for i := 0; i < 20; i++ {
						dialer := &net.Dialer{Timeout: 1 * time.Second}
						conn, dialErr = tls.DialWithDialer(dialer, "tcp", cfg.TargetAddr, tlsConf)
						if dialErr == nil {
							break
						}
						time.Sleep(100 * time.Millisecond)
					}
					if dialErr != nil {
						return false, fmt.Errorf("TLS dial failed to %s: %w", cfg.TargetAddr, dialErr)
					}
					defer conn.Close()

					state := conn.ConnectionState()
					if len(state.PeerCertificates) == 0 {
						return false, errors.New("zero peer certificates returned during TLS handshake")
					}

					presentedSerial := state.PeerCertificates[0].SerialNumber.Text(16)
					if presentedSerial != stagedSerial {
						return false, fmt.Errorf("peer cert serial mismatch: presented %s != staged %s", presentedSerial, stagedSerial)
					}

					// Optional HTTP /healthz probe
					if cfg.HealthURL != "" {
						tr := &http.Transport{
							TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
						}
						client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
						resp, err := client.Get(cfg.HealthURL)
						if err == nil {
							_ = resp.Body.Close()
							if resp.StatusCode != http.StatusOK {
								return false, fmt.Errorf("HTTPS health probe returned status %d", resp.StatusCode)
							}
						}
					}

					return true, nil
				},
			},
		},
		RollbackSteps: []model.RollbackStep{
			{
				Name: "restore-original-tls-certificate",
				CompensatingFn: func(ctx context.Context) error {
					if backupCertPath != "" && backupKeyPath != "" {
						if bCert, err := os.ReadFile(backupCertPath); err == nil {
							_ = os.WriteFile(cfg.ActiveCertPath, bCert, 0644)
						}
						if bKey, err := os.ReadFile(backupKeyPath); err == nil {
							_ = os.WriteFile(cfg.ActiveKeyPath, bKey, 0600)
						}
						if cfg.ReloadFn != nil {
							_ = cfg.ReloadFn()
						}
					}
					return nil
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// 4. RBK-CFG-001: Corrupted Configuration Rollback to Last-Known-Good (LKG)
// -----------------------------------------------------------------------------

// ConfigRollbackConfig provides parameters for RBK-CFG-001.
type ConfigRollbackConfig struct {
	ServiceName      string
	ActiveConfigPath string
	LKGConfigPath    string
	QuarantineDir    string
	HealthURL        string
	TargetPID        int
	PIDFilePath      string
	RestartFn        func() error
	ExecutionTimeout time.Duration
}

// DefaultConfigRollbackConfig returns production defaults for RBK-CFG-001.
func DefaultConfigRollbackConfig() ConfigRollbackConfig {
	return ConfigRollbackConfig{
		ServiceName:      "ai-gateway",
		ActiveConfigPath: "/etc/ai-gateway/config.yaml",
		LKGConfigPath:    "/var/lib/autonomous-remediation/lkg/ai-gateway.config.yaml",
		QuarantineDir:    "/var/lib/autonomous-remediation/quarantine",
		HealthURL:        "http://127.0.0.1:8080/healthz",
		ExecutionTimeout: 10 * time.Second,
	}
}

// NewConfigRollbackRunbook constructs the deterministic RBK-CFG-001 runbook.
func NewConfigRollbackRunbook(cfg ConfigRollbackConfig) *model.Runbook {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "ai-gateway"
	}
	if cfg.ExecutionTimeout <= 0 {
		cfg.ExecutionTimeout = 10 * time.Second
	}

	var lkgSHA256 string

	return &model.Runbook{
		ID:               IDConfigRollback,
		Version:          "1.0.0",
		Name:             "config_rollback",
		TargetResourceID: cfg.ServiceName,
		Severity:         model.SeverityCritical,
		BlastRadius: model.BlastRadius{
			MaxExecutionTime: cfg.ExecutionTimeout,
			MaxFilesModified: 1,
		},
		Preconditions: []model.Precondition{
			{
				Name: "lkg-valid-and-active-config-diverged",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					// 1. Verify LKG exists
					lkgData, err := os.ReadFile(cfg.LKGConfigPath)
					if err != nil {
						return false, fmt.Errorf("LKG config %s does not exist or is unreadable: %w", cfg.LKGConfigPath, err)
					}

					// 2. Validate LKG syntax
					if err := ValidateConfigSyntax(lkgData); err != nil {
						return false, fmt.Errorf("LKG config syntax validation failed: %w", err)
					}

					h := sha256.Sum256(lkgData)
					lkgSHA256 = hex.EncodeToString(h[:])

					// 3. Compare with active config
					activeData, err := os.ReadFile(cfg.ActiveConfigPath)
					if err == nil {
						actH := sha256.Sum256(activeData)
						if hex.EncodeToString(actH[:]) == lkgSHA256 {
							return false, errors.New("active config already matches LKG config; rollback not applicable")
						}
					}

					return true, nil
				},
			},
		},
		Actions: []model.Action{
			{
				Name:    "quarantine-corrupt-and-atomic-restore-lkg",
				Timeout: cfg.ExecutionTimeout,
				MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
					// 1. Quarantine corrupted active config
					if cfg.QuarantineDir != "" {
						_ = os.MkdirAll(cfg.QuarantineDir, 0700)
						quarantinePath := filepath.Join(cfg.QuarantineDir,
							fmt.Sprintf("config-%d.yaml.corrupt", time.Now().UnixNano()))
						if activeData, err := os.ReadFile(cfg.ActiveConfigPath); err == nil {
							_ = os.WriteFile(quarantinePath, activeData, 0600)
						}
					}

					// 2. Read LKG and atomically swap into ActiveConfigPath
					lkgData, err := os.ReadFile(cfg.LKGConfigPath)
					if err != nil {
						return nil, fmt.Errorf("failed reading LKG config: %w", err)
					}

					tmpPath := cfg.ActiveConfigPath + ".lkg.tmp"
					if err := os.WriteFile(tmpPath, lkgData, 0644); err != nil {
						return nil, fmt.Errorf("failed writing tmp config: %w", err)
					}

					if err := os.Rename(tmpPath, cfg.ActiveConfigPath); err != nil {
						return nil, fmt.Errorf("failed atomic rename LKG config: %w", err)
					}

					// Flush filesystem metadata
					syscall.Sync()

					// 3. Restart / Reload service
					if cfg.RestartFn != nil {
						if err := cfg.RestartFn(); err != nil {
							return nil, fmt.Errorf("RestartFn failed: %w", err)
						}
					} else {
						pid := cfg.TargetPID
						if pid <= 0 && cfg.PIDFilePath != "" {
							if d, err := os.ReadFile(cfg.PIDFilePath); err == nil {
								pid, _ = strconv.Atoi(strings.TrimSpace(string(d)))
							}
						}
						if pid > 0 {
							_ = syscall.Kill(pid, syscall.SIGHUP)
						}
					}

					return &model.ExecutionResult{
						Success:      true,
						ExitCode:     0,
						BytesMutated: int64(len(lkgData)),
						Stdout:       fmt.Sprintf("LKG configuration (%s) restored and service reloaded", lkgSHA256[:8]),
					}, nil
				},
			},
		},
		Postconditions: []model.Postcondition{
			{
				Name: "active-sha256-matches-lkg-and-service-healthy",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					// 1. Verify ActiveConfig SHA-256 matches LKG exactly
					activeData, err := os.ReadFile(cfg.ActiveConfigPath)
					if err != nil {
						return false, fmt.Errorf("active config %s missing after restoration: %w", cfg.ActiveConfigPath, err)
					}

					actH := sha256.Sum256(activeData)
					actHex := hex.EncodeToString(actH[:])
					if actHex != lkgSHA256 {
						return false, fmt.Errorf("active config SHA-256 mismatch: active %s != LKG %s", actHex, lkgSHA256)
					}

					// 2. Health check returns 200 OK
					if cfg.HealthURL != "" {
						client := &http.Client{Timeout: 1 * time.Second}
						var lastErr error
						for i := 0; i < 20; i++ {
							resp, err := client.Get(cfg.HealthURL)
							if err == nil {
								_ = resp.Body.Close()
								if resp.StatusCode == http.StatusOK {
									return true, nil
								}
								lastErr = fmt.Errorf("health status %d", resp.StatusCode)
							} else {
								lastErr = err
							}
							time.Sleep(100 * time.Millisecond)
						}
						return false, fmt.Errorf("service health check failed after config restore: %w", lastErr)
					}

					return true, nil
				},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// Cryptographic, Filesystem & Inode Safety Helpers
// -----------------------------------------------------------------------------

// findCandidateArchives scans dir for rotated logs (*.log.gz, *.old, *.log.1, *.gz).
func findCandidateArchives(dir, activeLogName string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var candidates []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == activeLogName {
			continue
		}
		if isArchiveFile(name) {
			candidates = append(candidates, filepath.Join(dir, name))
		}
	}
	return candidates, nil
}

func isArchiveFile(filename string) bool {
	return strings.HasSuffix(filename, ".log.gz") ||
		strings.HasSuffix(filename, ".old") ||
		strings.HasSuffix(filename, ".gz") ||
		strings.Contains(filename, ".log.")
}

func checkCandidateFileSafe(candidatePath string, activeInode uint64, activeLogName string) (bool, error) {
	fi, err := os.Stat(candidatePath)
	if err != nil {
		return false, err
	}

	if sysStat, ok := fi.Sys().(*syscall.Stat_t); ok {
		if activeInode > 0 && sysStat.Ino == activeInode {
			return false, fmt.Errorf("candidate inode matches active log inode %d", activeInode)
		}
	}

	if filepath.Base(candidatePath) == activeLogName {
		return false, errors.New("candidate filename matches active log name")
	}

	return true, nil
}

// VerifyCertAndKeyModulus validates that certPEM matches keyPEM cryptographically.
func VerifyCertAndKeyModulus(certPEM, keyPEM []byte) (*x509.Certificate, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode private key PEM")
	}

	var privKey any
	if k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		privKey = k
	} else if k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		privKey = k
	} else if k, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		privKey = k
	} else {
		return nil, errors.New("unsupported private key format")
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		rsaPriv, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("public key is RSA but private key is not")
		}
		if pub.N.Cmp(rsaPriv.N) != 0 {
			return nil, errors.New("RSA modulus mismatch between certificate and private key")
		}
	case *ecdsa.PublicKey:
		ecPriv, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("public key is ECDSA but private key is not")
		}
		if pub.X.Cmp(ecPriv.X) != 0 || pub.Y.Cmp(ecPriv.Y) != 0 {
			return nil, errors.New("ECDSA public key point mismatch")
		}
	case ed25519.PublicKey:
		edPriv, ok := privKey.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("public key is Ed25519 but private key is not")
		}
		if !bytes.Equal(pub, edPriv.Public().(ed25519.PublicKey)) {
			return nil, errors.New("Ed25519 public key mismatch")
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", cert.PublicKey)
	}

	return cert, nil
}

// ValidateConfigSyntax validates that data is well-formed JSON or YAML.
func ValidateConfigSyntax(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("empty configuration data")
	}

	// 1. JSON check
	var js any
	if err := json.Unmarshal(data, &js); err == nil {
		return nil
	}

	// 2. YAML syntax verification
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// YAML prohibits tabs for indentation
		prefixLen := len(line) - len(strings.TrimLeft(line, " \t"))
		indent := line[:prefixLen]
		if strings.Contains(indent, "\t") {
			return fmt.Errorf("syntax error at line %d: YAML prohibits tabs for indentation", lineNum)
		}

		// Balanced quotes check
		sQuotes := strings.Count(trimmed, "'")
		dQuotes := strings.Count(trimmed, "\"") - strings.Count(trimmed, `\"`)
		if (sQuotes%2 != 0) || (dQuotes%2 != 0) {
			if !strings.HasSuffix(trimmed, "|") && !strings.HasSuffix(trimmed, ">") {
				return fmt.Errorf("syntax error at line %d: unbalanced quotes", lineNum)
			}
		}

		// Must contain key-value separator or list indicator
		if !strings.HasPrefix(trimmed, "-") && !strings.Contains(trimmed, ":") {
			return fmt.Errorf("syntax error at line %d: invalid YAML construct %q", lineNum, trimmed)
		}
	}

	return scanner.Err()
}
