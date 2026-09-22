package rollback

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"autonomous-remediation-engine/internal/model"
)

// RollbackEngine replays compensating actions in reverse order when postconditions fail.
type RollbackEngine struct {
	journal *Journal
}

// NewRollbackEngine creates an instance of the rollback engine.
func NewRollbackEngine(journal *Journal) *RollbackEngine {
	return &RollbackEngine{
		journal: journal,
	}
}

// ExecuteRollback executes all compensating actions in reverse order (S_n ... S_1).
func (r *RollbackEngine) ExecuteRollback(ctx context.Context, record *WALRecord) error {
	if record == nil {
		return nil
	}

	if r.journal != nil {
		_ = r.journal.UpdateState(record.TxID, StateRollingBack)
	}

	totalSteps := len(record.Steps)
	// Replay in strictly reverse order
	for i := totalSteps - 1; i >= 0; i-- {
		step := record.Steps[i]

		if err := r.executeSingleStep(ctx, step); err != nil {
			if r.journal != nil {
				_ = r.journal.UpdateState(record.TxID, StateFailed)
			}
			return fmt.Errorf("compensating step %d (%s) failed during rollback: %w", i, step.Name, err)
		}
	}

	if r.journal != nil {
		_ = r.journal.UpdateState(record.TxID, StateRolledBack)
	}

	return nil
}

func (r *RollbackEngine) executeSingleStep(ctx context.Context, step model.RollbackStep) error {
	// 1. Programmatic CompensatingFn
	if step.CompensatingFn != nil {
		return step.CompensatingFn(ctx)
	}

	// 2. File restoration from staged backup
	if step.TargetPath != "" && step.StagedBackupPath != "" {
		return restoreFile(step.StagedBackupPath, step.TargetPath)
	}

	// 3. Command execution
	if step.Binary != "" {
		cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		cmd := exec.CommandContext(cmdCtx, step.Binary, step.Args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("command %s failed with output %q: %w", step.Binary, string(output), err)
		}
		return nil
	}

	return nil
}

func restoreFile(backupPath, targetPath string) error {
	src, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed opening backup file %s: %w", backupPath, err)
	}
	defer src.Close()

	dest, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed opening target file %s for restoration: %w", targetPath, err)
	}
	defer dest.Close()

	if _, err := io.Copy(dest, src); err != nil {
		return fmt.Errorf("failed restoring file contents: %w", err)
	}

	if err := dest.Sync(); err != nil {
		return fmt.Errorf("failed syncing restored file: %w", err)
	}

	return nil
}
