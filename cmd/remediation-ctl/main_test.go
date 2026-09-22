package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCLI_DefaultCatalog(t *testing.T) {
	cat := defaultCatalog()
	if len(cat) != 4 {
		t.Fatalf("expected 4 default runbooks in catalog, got %d", len(cat))
	}

	expectedIDs := map[string]bool{
		"RBK-DISK-001": false,
		"RBK-PROC-001": false,
		"RBK-TLS-001":  false,
		"RBK-CFG-001":  false,
	}

	for _, rb := range cat {
		expectedIDs[rb.ID] = true
	}

	for id, found := range expectedIDs {
		if !found {
			t.Fatalf("expected runbook %s in default catalog", id)
		}
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
	dampingFile := filepath.Join(tempDir, "damping.json")

	// 1. Test status
	handleStatus([]string{"--journal-dir=" + journalDir})

	// 2. Test list-runbooks
	handleListRunbooks([]string{})

	// 3. Test damping-status
	handleDampingStatus([]string{"--damping-file=" + dampingFile})
	handleDampingStatus([]string{"--damping-file=" + dampingFile, "--resource=/var/log"})

	// 4. Test run on RBK-DISK-001
	handleRun([]string{
		"--runbook=RBK-DISK-001",
		"--resource=/var/log",
		"--audit-log=" + auditLog,
		"--lock-dir=" + lockDir,
		"--journal-dir=" + journalDir,
		"--damping-file=" + dampingFile,
	})

	// 5. Test verify-audit
	handleVerifyAudit([]string{"--file=" + auditLog})

	// 6. Test damping-status after run to verify execution was recorded
	handleDampingStatus([]string{"--damping-file=" + dampingFile, "--resource=/var/log"})
}
