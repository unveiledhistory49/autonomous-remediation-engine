package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}

	if cfg.HTTPAddr != "127.0.0.1:9443" {
		t.Errorf("expected default HTTPAddr to be 127.0.0.1:9443, got %s", cfg.HTTPAddr)
	}

	if cfg.PollInterval != 2*time.Second {
		t.Errorf("expected default PollInterval 2s, got %v", cfg.PollInterval)
	}

	if len(cfg.MonitoredServices) != 2 {
		t.Fatalf("expected 2 default monitored services, got %d", len(cfg.MonitoredServices))
	}
	if cfg.MonitoredServices[0].Name != "ai-gateway" {
		t.Errorf("expected first service to be ai-gateway, got %s", cfg.MonitoredServices[0].Name)
	}
	if cfg.MonitoredServices[1].Name != "guardrail-proxy" {
		t.Errorf("expected second service to be guardrail-proxy, got %s", cfg.MonitoredServices[1].Name)
	}

	if len(cfg.MonitoredPaths) != 1 {
		t.Fatalf("expected 1 default monitored path, got %d", len(cfg.MonitoredPaths))
	}
	if cfg.MonitoredPaths[0].Path != "/var/log" {
		t.Errorf("expected monitored path /var/log, got %s", cfg.MonitoredPaths[0].Path)
	}

	if os.Geteuid() == 0 {
		if cfg.UnixSocketPath != "/run/remediation.sock" {
			t.Errorf("expected root socket /run/remediation.sock, got %s", cfg.UnixSocketPath)
		}
		if cfg.LockDir != "/var/run/remediation/" {
			t.Errorf("expected root lock dir /var/run/remediation/, got %s", cfg.LockDir)
		}
	} else {
		if cfg.UnixSocketPath != "/tmp/remediation.sock" {
			t.Errorf("expected non-root socket /tmp/remediation.sock, got %s", cfg.UnixSocketPath)
		}
	}
}

func TestParseConfig_JSON(t *testing.T) {
	jsonContent := `{
		"unix_socket_path": "/tmp/custom.sock",
		"http_addr": "127.0.0.1:8443",
		"hmac_secret": "supersecretkey123",
		"poll_interval": "5s",
		"monitored_paths": [
			{"path": "/tmp/test-log", "min_free_pct": 20.5}
		],
		"monitored_services": [
			{"name": "test-svc", "health_url": "http://127.0.0.1:9000/healthz", "port": 9000}
		]
	}`

	cfg, err := ParseConfig([]byte(jsonContent))
	if err != nil {
		t.Fatalf("ParseConfig JSON failed: %v", err)
	}

	if cfg.UnixSocketPath != "/tmp/custom.sock" {
		t.Errorf("expected socket /tmp/custom.sock, got %s", cfg.UnixSocketPath)
	}
	if cfg.HTTPAddr != "127.0.0.1:8443" {
		t.Errorf("expected http addr 127.0.0.1:8443, got %s", cfg.HTTPAddr)
	}
	if cfg.HMACSecret != "supersecretkey123" {
		t.Errorf("expected HMAC secret supersecretkey123, got %s", cfg.HMACSecret)
	}
	if cfg.PollInterval != 5*time.Second {
		t.Errorf("expected poll interval 5s, got %v", cfg.PollInterval)
	}
	if len(cfg.MonitoredPaths) != 1 || cfg.MonitoredPaths[0].Path != "/tmp/test-log" {
		t.Errorf("unexpected monitored paths: %+v", cfg.MonitoredPaths)
	}
	if len(cfg.MonitoredServices) != 1 || cfg.MonitoredServices[0].Name != "test-svc" {
		t.Errorf("unexpected monitored services: %+v", cfg.MonitoredServices)
	}
}

func TestParseConfig_YAML(t *testing.T) {
	yamlContent := `
# Remediation Engine Config
unix_socket_path: /tmp/test-yaml.sock
http_addr: 127.0.0.1:7443
hmac_secret: yaml-secret-token
poll_interval: 3s
lock_dir: /tmp/test-yaml-locks/

monitored_services:
  - name: ai-gateway-prod
    health_url: http://127.0.0.1:8080/healthz
    pid_file: /tmp/gateway.pid
    port: 8080
  - name: guardrail-proxy-prod
    health_url: http://127.0.0.1:8081/healthz
    pid_file: /tmp/guardrail.pid
    port: 8081

monitored_paths:
  - path: /tmp/data
    min_free_pct: 25.0
`

	cfg, err := ParseConfig([]byte(yamlContent))
	if err != nil {
		t.Fatalf("ParseConfig YAML failed: %v", err)
	}

	if cfg.UnixSocketPath != "/tmp/test-yaml.sock" {
		t.Errorf("expected socket /tmp/test-yaml.sock, got %s", cfg.UnixSocketPath)
	}
	if cfg.HTTPAddr != "127.0.0.1:7443" {
		t.Errorf("expected http addr 127.0.0.1:7443, got %s", cfg.HTTPAddr)
	}
	if cfg.HMACSecret != "yaml-secret-token" {
		t.Errorf("expected hmac secret yaml-secret-token, got %s", cfg.HMACSecret)
	}
	if cfg.PollInterval != 3*time.Second {
		t.Errorf("expected poll interval 3s, got %v", cfg.PollInterval)
	}
	if cfg.LockDir != "/tmp/test-yaml-locks/" {
		t.Errorf("expected lock dir /tmp/test-yaml-locks/, got %s", cfg.LockDir)
	}
	if len(cfg.MonitoredServices) != 2 {
		t.Fatalf("expected 2 monitored services, got %d", len(cfg.MonitoredServices))
	}
	if cfg.MonitoredServices[0].Name != "ai-gateway-prod" || cfg.MonitoredServices[0].Port != 8080 {
		t.Errorf("unexpected first service: %+v", cfg.MonitoredServices[0])
	}
	if len(cfg.MonitoredPaths) != 1 || cfg.MonitoredPaths[0].Path != "/tmp/data" || cfg.MonitoredPaths[0].MinFreePct != 25.0 {
		t.Errorf("unexpected monitored paths: %+v", cfg.MonitoredPaths)
	}
}

func TestLoadConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.yaml")

	content := `
unix_socket_path: /tmp/file-test.sock
http_addr: 127.0.0.1:6443
hmac_secret: file-secret
`
	if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.UnixSocketPath != "/tmp/file-test.sock" {
		t.Errorf("expected socket /tmp/file-test.sock, got %s", cfg.UnixSocketPath)
	}
	if cfg.HTTPAddr != "127.0.0.1:6443" {
		t.Errorf("expected addr 127.0.0.1:6443, got %s", cfg.HTTPAddr)
	}

	// Empty path should return default config
	defCfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig(\"\") failed: %v", err)
	}
	if defCfg == nil {
		t.Fatal("expected non-nil default config")
	}

	// Non-existent path should return error
	_, err = LoadConfig(filepath.Join(tmpDir, "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}
