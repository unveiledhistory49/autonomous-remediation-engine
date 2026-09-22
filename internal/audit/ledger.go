package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"autonomous-remediation-engine/internal/model"
)

// DefaultGenesisSalt is used in the genesis hash calculation.
const DefaultGenesisSalt = "REMEDIATION_GENESIS_2026"

// AuditEntry represents a single cryptographically chained record in the audit ledger.
type AuditEntry struct {
	Seq            uint64 `json:"seq"`
	Timestamp      string `json:"timestamp"`
	HostUUID       string `json:"host_uuid"`
	ResourceID     string `json:"resource_id"`
	RunbookID      string `json:"runbook_id"`
	State          string `json:"state"`
	PayloadDigest  string `json:"payload_digest"`
	PrevRecordHash string `json:"prev_record_hash"`
	RecordHash     string `json:"record_hash"`
}

// GenesisHash generates the baseline root hash H_0 for a host.
func GenesisHash(hostUUID, bootInfo string) string {
	h := sha256.New()
	h.Write([]byte(DefaultGenesisSalt))
	h.Write([]byte(hostUUID))
	h.Write([]byte(bootInfo))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeRecordHash computes H_i = SHA-256(H_{i-1} || Seq || Timestamp || ResourceID || State || RunbookID || PayloadDigest).
func ComputeRecordHash(prevHash string, seq uint64, timestamp, resourceID, state, runbookID, payloadDigest string) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seq)
	h.Write(seqBuf[:])
	h.Write([]byte(timestamp))
	h.Write([]byte(resourceID))
	h.Write([]byte(state))
	h.Write([]byte(runbookID))
	h.Write([]byte(payloadDigest))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputePayloadDigest computes SHA-256(RawAlertJSON || ExecutionStdout || ExecutionStderr).
func ComputePayloadDigest(rawAlert, stdout, stderr string) string {
	h := sha256.New()
	h.Write([]byte(rawAlert))
	h.Write([]byte(stdout))
	h.Write([]byte(stderr))
	return hex.EncodeToString(h.Sum(nil))
}

// Ledger manages the append-only, hash-chained audit journal on disk.
type Ledger struct {
	mu       sync.Mutex
	file     *os.File
	filePath string
	hostUUID string
	lastHash string
	nextSeq  uint64
}

// NewLedger opens or creates an audit ledger file at filePath.
// If the ledger already exists, it reads to the tail to initialize lastHash and nextSeq.
func NewLedger(filePath, hostUUID string) (*Ledger, error) {
	if hostUUID == "" {
		hostUUID = "localhost-arm64"
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory for audit ledger: %w", err)
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit ledger file %s: %w", filePath, err)
	}

	l := &Ledger{
		file:     f,
		filePath: filePath,
		hostUUID: hostUUID,
		lastHash: GenesisHash(hostUUID, "INIT"),
		nextSeq:  0,
	}

	// If file is non-empty, scan to find tail state
	fi, err := f.Stat()
	if err == nil && fi.Size() > 0 {
		if _, err := f.Seek(0, 0); err != nil {
			f.Close()
			return nil, fmt.Errorf("failed to seek audit file: %w", err)
		}

		scanner := bufio.NewScanner(f)
		var lastSeq uint64
		var hasEntries bool

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var rec AuditEntry
			if err := json.Unmarshal(line, &rec); err != nil {
				f.Close()
				return nil, fmt.Errorf("existing audit file contains malformed record: %w", err)
			}
			l.lastHash = rec.RecordHash
			lastSeq = rec.Seq
			hasEntries = true
		}

		if err := scanner.Err(); err != nil {
			f.Close()
			return nil, fmt.Errorf("failed reading existing audit entries: %w", err)
		}

		if hasEntries {
			l.nextSeq = lastSeq + 1
		}
	}

	return l, nil
}

// Append creates and synchronously commits an audit record to the ledger.
// It uses file.Sync() to guarantee persistence to non-volatile storage.
func (l *Ledger) Append(resourceID, runbookID string, state model.ExecutionState, payloadDigest string) (*AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return nil, errors.New("ledger is closed")
	}

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	recHash := ComputeRecordHash(
		l.lastHash,
		l.nextSeq,
		timestamp,
		resourceID,
		string(state),
		runbookID,
		payloadDigest,
	)

	entry := &AuditEntry{
		Seq:            l.nextSeq,
		Timestamp:      timestamp,
		HostUUID:       l.hostUUID,
		ResourceID:     resourceID,
		RunbookID:      runbookID,
		State:          string(state),
		PayloadDigest:  payloadDigest,
		PrevRecordHash: l.lastHash,
		RecordHash:     recHash,
	}

	bytes, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize audit entry: %w", err)
	}

	// Append line delimiter
	bytes = append(bytes, '\n')

	if _, err := l.file.Write(bytes); err != nil {
		return nil, fmt.Errorf("failed to write audit entry to disk: %w", err)
	}

	// Non-volatile disk synchronization
	if err := l.file.Sync(); err != nil {
		return nil, fmt.Errorf("failed to sync audit file: %w", err)
	}

	l.lastHash = recHash
	l.nextSeq++

	return entry, nil
}

// Close closes the underlying ledger file descriptor.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// LastHash returns the latest record hash in the chain.
func (l *Ledger) LastHash() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastHash
}

// NextSeq returns the next sequence number to be issued.
func (l *Ledger) NextSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.nextSeq
}
