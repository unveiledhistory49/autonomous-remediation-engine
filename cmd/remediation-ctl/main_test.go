package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"autonomous-remediation-engine/internal/audit"
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

func TestCLI_Triage(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cli-triage-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	auditLog := filepath.Join(tempDir, "audit.log")
	lockDir := filepath.Join(tempDir, "locks")
	journalDir := filepath.Join(tempDir, "journal")
	dampingFile := filepath.Join(tempDir, "damping.json")
	incidentFile := filepath.Join(tempDir, "incident.log")

	if err := os.WriteFile(incidentFile, []byte("2026-09-22 storage: /var/log volume saturated at 99% capacity"), 0644); err != nil {
		t.Fatalf("failed to write incident file: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id": "chatcmpl-mock",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":              "assistant",
						"content":           `{"runbook_id": "RBK-DISK-001", "target_resource": "/var/log", "severity": "HIGH", "diagnosis": "Log volume saturation"}`,
						"reasoning_content": "Evaluated disk volume pressure on /var/log. Triggering safe log prune.",
					},
					"finish_reason": "stop",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// 1. Dry run via file incident
	handleTriage([]string{
		"--incident=" + incidentFile,
		"--api-key=test-key",
		"--base-url=" + server.URL,
		"--model=test-model",
	})

	// 2. Live execution via string incident
	handleTriage([]string{
		"--incident=Disk /var/log out of space",
		"--api-key=test-key",
		"--base-url=" + server.URL,
		"--model=test-model",
		"--execute",
		"--audit-log=" + auditLog,
		"--lock-dir=" + lockDir,
		"--journal-dir=" + journalDir,
		"--damping-file=" + dampingFile,
	})

	// 3. Verify audit ledger produced by AI execution
	report, err := audit.VerifyLedgerFile(auditLog)
	if err != nil {
		t.Fatalf("failed to verify audit ledger from triage execution: %v", err)
	}
	if report.TotalRecords == 0 {
		t.Fatalf("expected audit records after triage execute, got 0")
	}
}

