package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_DefaultCatalog(t *testing.T) {
	cat := defaultCatalog()
	if len(cat) < 2 {
		t.Fatalf("expected at least 2 default runbooks in catalog, got %d", len(cat))
	}

	foundDisk := false
	for _, rb := range cat {
		if rb.ID == "RBK-DISK-001" {
			foundDisk = true
		}
	}
	if !foundDisk {
		t.Fatalf("expected RBK-DISK-001 in default catalog")
	}
}

func TestCLI_Subcommands(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cli-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	auditLog := filepath.Join(tempDir, "audit.log")
	lockDir := filepath.Join(tempDir, "locks")
	journalDir := filepath.Join(tempDir, "journal")

	// 1. Test status
	handleStatus([]string{"--journal-dir=" + journalDir})

	// 2. Test run
	handleRun([]string{
		"--runbook=RBK-DISK-001",
		"--resource=/var/log",
		"--audit-log=" + auditLog,
		"--lock-dir=" + lockDir,
		"--journal-dir=" + journalDir,
	})

	// 3. Test verify-audit
	handleVerifyAudit([]string{"--file=" + auditLog})
}
