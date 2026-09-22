package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"autonomous-remediation-engine/internal/model"
)

func TestLedger_NormalChainingAndVerification(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logPath := filepath.Join(tempDir, "audit.log")
	ledger, err := NewLedger(logPath, "node-arm64-test")
	if err != nil {
		t.Fatalf("failed to create ledger: %v", err)
	}

	states := []model.ExecutionState{
		model.StateDetected,
		model.StateEvaluating,
		model.StatePrecheckPassed,
		model.StateExecuting,
		model.StatePostcheckPassed,
		model.StateCommitted,
	}

	var prevHash string
	for i, st := range states {
		digest := ComputePayloadDigest(`{"alert":"test"}`, "stdout-sample", "stderr-sample")
		entry, err := ledger.Append("/var/log", "RBK-DISK-001", st, digest)
		if err != nil {
			t.Fatalf("append %d failed: %v", i, err)
		}

		if entry.Seq != uint64(i) {
			t.Fatalf("expected seq %d, got %d", i, entry.Seq)
		}

		if i > 0 && entry.PrevRecordHash != prevHash {
			t.Fatalf("expected prev hash %s, got %s", prevHash, entry.PrevRecordHash)
		}

		prevHash = entry.RecordHash
	}

	if err := ledger.Close(); err != nil {
		t.Fatalf("failed to close ledger: %v", err)
	}

	// Verify the entire file
	result, err := VerifyLedgerFile(logPath)
	if err != nil {
		t.Fatalf("verification should succeed, got error: %v", err)
	}

	if !result.Valid {
		t.Fatalf("expected result.Valid == true")
	}

	if result.TotalRecords != uint64(len(states)) {
		t.Fatalf("expected %d records, got %d", len(states), result.TotalRecords)
	}

	if result.TailHash != prevHash {
		t.Fatalf("expected tail hash %s, got %s", prevHash, result.TailHash)
	}
}

func TestLedger_ResumeExistingLog(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-resume-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logPath := filepath.Join(tempDir, "audit.log")

	// Phase 1: create 3 entries
	l1, err := NewLedger(logPath, "host-01")
	if err != nil {
		t.Fatalf("failed to create l1: %v", err)
	}
	_, _ = l1.Append("res1", "rbk1", model.StateDetected, "digest1")
	_, _ = l1.Append("res1", "rbk1", model.StateEvaluating, "digest2")
	e3, _ := l1.Append("res1", "rbk1", model.StatePrecheckPassed, "digest3")
	_ = l1.Close()

	// Phase 2: reopen and append 2 more entries
	l2, err := NewLedger(logPath, "host-01")
	if err != nil {
		t.Fatalf("failed to resume ledger: %v", err)
	}

	if l2.NextSeq() != 3 {
		t.Fatalf("expected NextSeq=3, got %d", l2.NextSeq())
	}
	if l2.LastHash() != e3.RecordHash {
		t.Fatalf("expected LastHash=%s, got %s", e3.RecordHash, l2.LastHash())
	}

	e4, err := l2.Append("res1", "rbk1", model.StateExecuting, "digest4")
	if err != nil {
		t.Fatalf("failed to append to resumed ledger: %v", err)
	}
	if e4.PrevRecordHash != e3.RecordHash {
		t.Fatalf("hash chain break across sessions: expected %s, got %s", e3.RecordHash, e4.PrevRecordHash)
	}
	_ = l2.Close()

	// Verify complete log
	res, err := VerifyLedgerFile(logPath)
	if err != nil {
		t.Fatalf("verification of resumed ledger failed: %v", err)
	}
	if res.TotalRecords != 4 {
		t.Fatalf("expected 4 records, got %d", res.TotalRecords)
	}
}

func TestLedger_TamperDetection_PayloadModified(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-tamper-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logPath := filepath.Join(tempDir, "audit.log")
	ledger, _ := NewLedger(logPath, "host-tamper")
	_, _ = ledger.Append("res1", "rbk1", model.StateDetected, "d1")
	_, _ = ledger.Append("res1", "rbk1", model.StateEvaluating, "d2")
	_, _ = ledger.Append("res1", "rbk1", model.StateCommitted, "d3")
	_ = ledger.Close()

	// Tamper: read lines, modify middle line state
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var rec AuditEntry
	_ = json.Unmarshal([]byte(lines[1]), &rec)
	rec.State = string(model.StateRolledBack) // Forgery
	tamperedBytes, _ := json.Marshal(rec)
	lines[1] = string(tamperedBytes)

	tamperedContent := strings.Join(lines, "\n") + "\n"
	_ = os.WriteFile(logPath, []byte(tamperedContent), 0600)

	// Verification should fail
	_, err = VerifyLedgerFile(logPath)
	if err == nil {
		t.Fatalf("expected verification failure on tampered payload, but succeeded")
	}
	if !strings.Contains(err.Error(), "tamper detected at seq 1") {
		t.Fatalf("expected tamper error at seq 1, got: %v", err)
	}
}

func TestLedger_TamperDetection_LineOmission(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-omission-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logPath := filepath.Join(tempDir, "audit.log")
	ledger, _ := NewLedger(logPath, "host-omission")
	_, _ = ledger.Append("res1", "rbk1", model.StateDetected, "d1")
	_, _ = ledger.Append("res1", "rbk1", model.StateEvaluating, "d2")
	_, _ = ledger.Append("res1", "rbk1", model.StateCommitted, "d3")
	_ = ledger.Close()

	// Tamper: omit line 1 (seq 1)
	content, _ := os.ReadFile(logPath)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	omittedContent := lines[0] + "\n" + lines[2] + "\n"
	_ = os.WriteFile(logPath, []byte(omittedContent), 0600)

	_, err = VerifyLedgerFile(logPath)
	if err == nil {
		t.Fatalf("expected verification failure on omitted record, but succeeded")
	}
	if !strings.Contains(err.Error(), "sequence discontinuity") {
		t.Fatalf("expected sequence discontinuity error, got: %v", err)
	}
}
