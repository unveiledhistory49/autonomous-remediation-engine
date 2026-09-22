package rollback

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"autonomous-remediation-engine/internal/model"
)

func TestWALJournal_StageAndUpdate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wal-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	j, err := NewJournal(tempDir)
	if err != nil {
		t.Fatalf("failed to create journal: %v", err)
	}

	txID := "tx-1001"
	steps := []model.RollbackStep{
		{Name: "restore-config", TargetPath: "/etc/app.conf"},
	}

	rec, err := j.Stage(txID, "RBK-001", "/etc/app.conf", steps)
	if err != nil {
		t.Fatalf("failed to stage WAL: %v", err)
	}

	if rec.State != StatePrepared {
		t.Fatalf("expected state PREPARED, got %s", rec.State)
	}

	// Verify file exists on disk
	walPath := j.PathForTx(txID)
	if _, err := os.Stat(walPath); err != nil {
		t.Fatalf("expected wal file to exist at %s: %v", walPath, err)
	}

	// Update state to COMMITTED
	if err := j.UpdateState(txID, StateCommitted); err != nil {
		t.Fatalf("failed to update state: %v", err)
	}

	readRec, err := j.Read(txID)
	if err != nil {
		t.Fatalf("failed to read updated record: %v", err)
	}

	if readRec.State != StateCommitted {
		t.Fatalf("expected COMMITTED, got %s", readRec.State)
	}
}

func TestWALJournal_ListPending(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wal-pending-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	j, err := NewJournal(tempDir)
	if err != nil {
		t.Fatalf("failed to create journal: %v", err)
	}

	_, _ = j.Stage("tx-p1", "rbk", "res1", nil)
	_, _ = j.Stage("tx-p2", "rbk", "res2", nil)
	_, _ = j.Stage("tx-c3", "rbk", "res3", nil)
	_ = j.UpdateState("tx-c3", StateCommitted)

	pending, err := j.ListPending()
	if err != nil {
		t.Fatalf("failed to list pending: %v", err)
	}

	if len(pending) != 2 {
		t.Fatalf("expected 2 pending transactions, got %d", len(pending))
	}
}

func TestRollbackEngine_ReverseOrderExecution(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rb-engine-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	j, _ := NewJournal(tempDir)
	engine := NewRollbackEngine(j)

	var executionLog []string

	steps := []model.RollbackStep{
		{
			Name: "step-1",
			CompensatingFn: func(ctx context.Context) error {
				executionLog = append(executionLog, "step-1")
				return nil
			},
		},
		{
			Name: "step-2",
			CompensatingFn: func(ctx context.Context) error {
				executionLog = append(executionLog, "step-2")
				return nil
			},
		},
		{
			Name: "step-3",
			CompensatingFn: func(ctx context.Context) error {
				executionLog = append(executionLog, "step-3")
				return nil
			},
		},
	}

	txID := "tx-reverse"
	rec, err := j.Stage(txID, "RBK-REV", "test-res", steps)
	if err != nil {
		t.Fatalf("failed to stage: %v", err)
	}

	ctx := context.Background()
	if err := engine.ExecuteRollback(ctx, rec); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	expectedOrder := []string{"step-3", "step-2", "step-1"}
	if !reflect.DeepEqual(executionLog, expectedOrder) {
		t.Fatalf("expected execution order %v, got %v", expectedOrder, executionLog)
	}

	// Verify journal state updated to ROLLED_BACK
	finalRec, _ := j.Read(txID)
	if finalRec.State != StateRolledBack {
		t.Fatalf("expected state ROLLED_BACK, got %s", finalRec.State)
	}
}

func TestRollbackEngine_FileRestoration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rb-file-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	j, _ := NewJournal(filepath.Join(tempDir, "wal"))
	engine := NewRollbackEngine(j)

	// 1. Create original target file
	targetFile := filepath.Join(tempDir, "config.yaml")
	originalContent := "port: 8080\nstatus: healthy\n"
	if err := os.WriteFile(targetFile, []byte(originalContent), 0600); err != nil {
		t.Fatalf("failed writing target file: %v", err)
	}

	// 2. Stage backup
	backupDir := filepath.Join(tempDir, "staging")
	backupPath, err := StageFileBackup(targetFile, backupDir)
	if err != nil {
		t.Fatalf("failed to stage backup: %v", err)
	}

	// 3. Mutate (corrupt) target file
	corruptedContent := "port: 8080\nBROKEN_SYNTAX: %%%"
	if err := os.WriteFile(targetFile, []byte(corruptedContent), 0600); err != nil {
		t.Fatalf("failed mutating target: %v", err)
	}

	// 4. Stage and execute rollback
	step := model.RollbackStep{
		Name:             "restore-config-file",
		TargetPath:       targetFile,
		StagedBackupPath: backupPath,
	}

	rec, _ := j.Stage("tx-file-restore", "RBK-CFG", targetFile, []model.RollbackStep{step})
	ctx := context.Background()
	if err := engine.ExecuteRollback(ctx, rec); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	// 5. Verify restored file
	restoredBytes, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatalf("failed reading restored file: %v", err)
	}

	if string(restoredBytes) != originalContent {
		t.Fatalf("expected restored content %q, got %q", originalContent, string(restoredBytes))
	}
}

func TestRollbackEngine_StepFailure(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rb-fail-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	j, _ := NewJournal(tempDir)
	engine := NewRollbackEngine(j)

	steps := []model.RollbackStep{
		{
			Name: "failing-step",
			CompensatingFn: func(ctx context.Context) error {
				return errors.New("disk hardware fault")
			},
		},
	}

	txID := "tx-fault"
	rec, _ := j.Stage(txID, "RBK-FAULT", "res", steps)
	ctx := context.Background()

	err = engine.ExecuteRollback(ctx, rec)
	if err == nil {
		t.Fatalf("expected rollback error, got nil")
	}

	finalRec, _ := j.Read(txID)
	if finalRec.State != StateFailed {
		t.Fatalf("expected state FAILED, got %s", finalRec.State)
	}
}
