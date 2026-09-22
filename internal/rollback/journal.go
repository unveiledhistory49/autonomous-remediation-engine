package rollback

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"autonomous-remediation-engine/internal/model"
)

// WAL states
const (
	StatePrepared    = "PREPARED"
	StateCommitted   = "COMMITTED"
	StateRollingBack = "ROLLING_BACK"
	StateRolledBack  = "ROLLED_BACK"
	StateFailed      = "FAILED"
)

// WALRecord represents a persisted Write-Ahead Log transaction.
type WALRecord struct {
	TxID       string               `json:"txid"`
	RunbookID  string               `json:"runbook_id"`
	ResourceID string               `json:"resource_id"`
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
	State      string               `json:"state"`
	Steps      []model.RollbackStep `json:"steps"`
}

// Journal manages Write-Ahead Log persistence to non-volatile disk.
type Journal struct {
	dir string
	mu  sync.Mutex
}

// NewJournal initializes a WAL journal in the specified directory.
func NewJournal(dir string) (*Journal, error) {
	if dir == "" {
		dir = "/tmp/remediation-journal"
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create journal directory %s: %w", dir, err)
	}
	return &Journal{dir: dir}, nil
}

// PathForTx returns the deterministic file path for a transaction's WAL file.
func (j *Journal) PathForTx(txID string) string {
	return filepath.Join(j.dir, txID+".wal")
}

// Stage writes a new WAL record to disk and synchronously calls fsync before mutations occur.
func (j *Journal) Stage(txID, runbookID, resourceID string, steps []model.RollbackStep) (*WALRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now().UTC()
	rec := &WALRecord{
		TxID:       txID,
		RunbookID:  runbookID,
		ResourceID: resourceID,
		CreatedAt:  now,
		UpdatedAt:  now,
		State:      StatePrepared,
		Steps:      steps,
	}

	if err := j.writeAndSync(rec); err != nil {
		return nil, fmt.Errorf("failed to stage WAL record for tx %s: %w", txID, err)
	}

	return rec, nil
}

// UpdateState modifies the transaction state and synchronizes the change to disk.
func (j *Journal) UpdateState(txID, newState string) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	rec, err := j.readUnsafe(txID)
	if err != nil {
		return err
	}

	rec.State = newState
	rec.UpdatedAt = time.Now().UTC()

	return j.writeAndSync(rec)
}

// Read loads a WAL record from disk.
func (j *Journal) Read(txID string) (*WALRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	return j.readUnsafe(txID)
}

func (j *Journal) readUnsafe(txID string) (*WALRecord, error) {
	filePath := j.PathForTx(txID)
	bytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read WAL file %s: %w", filePath, err)
	}

	var rec WALRecord
	if err := json.Unmarshal(bytes, &rec); err != nil {
		return nil, fmt.Errorf("corrupted WAL JSON in %s: %w", filePath, err)
	}

	return &rec, nil
}

func (j *Journal) writeAndSync(rec *WALRecord) error {
	filePath := j.PathForTx(rec.TxID)
	bytes, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize WAL record: %w", err)
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open WAL file %s: %w", filePath, err)
	}
	defer f.Close()

	if _, err := f.Write(bytes); err != nil {
		return fmt.Errorf("failed to write WAL file: %w", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to fsync WAL file: %w", err)
	}

	return nil
}

// ListPending returns all transactions currently in PREPARED or ROLLING_BACK states.
func (j *Journal) ListPending() ([]*WALRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read journal directory: %w", err)
	}

	var pending []*WALRecord
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wal") {
			continue
		}

		txID := strings.TrimSuffix(entry.Name(), ".wal")
		rec, err := j.readUnsafe(txID)
		if err != nil {
			continue
		}

		if rec.State == StatePrepared || rec.State == StateRollingBack {
			pending = append(pending, rec)
		}
	}

	return pending, nil
}

// StageFileBackup creates an atomic byte-for-byte copy of sourcePath in backupDir.
func StageFileBackup(sourcePath, backupDir string) (string, error) {
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create backup dir: %w", err)
	}

	srcFile, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file %s: %w", sourcePath, err)
	}
	defer srcFile.Close()

	destPath := filepath.Join(backupDir, filepath.Base(sourcePath)+".bak")
	destFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to open dest backup file %s: %w", destPath, err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, srcFile); err != nil {
		return "", fmt.Errorf("failed copying bytes: %w", err)
	}

	if err := destFile.Sync(); err != nil {
		return "", fmt.Errorf("failed syncing backup file: %w", err)
	}

	return destPath, nil
}
