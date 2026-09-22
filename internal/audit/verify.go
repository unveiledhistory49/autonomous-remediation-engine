package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// VerificationResult contains the cryptographic audit assessment.
type VerificationResult struct {
	Valid        bool      `json:"valid"`
	TotalRecords uint64    `json:"total_records"`
	GenesisHash  string    `json:"genesis_hash"`
	TailHash     string    `json:"tail_hash"`
	VerifiedAt   time.Time `json:"verified_at"`
}

// VerifyLedgerFile reads an audit log file from disk and checks the complete hash chain and sequence continuity.
func VerifyLedgerFile(filePath string) (*VerificationResult, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit file %s: %w", filePath, err)
	}
	defer f.Close()

	return VerifyLedgerReader(f)
}

// VerifyLedgerReader reads audit entries from an io.Reader and verifies the hash chain.
func VerifyLedgerReader(r io.Reader) (*VerificationResult, error) {
	scanner := bufio.NewScanner(r)
	var expectedPrevHash string
	var expectedSeq uint64 = 0
	var firstPrevHash string
	var lastHash string

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var rec AuditEntry
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("malformed JSON record at seq %d: %w", expectedSeq, err)
		}

		// 1. Verify sequence monotonicity
		if rec.Seq != expectedSeq {
			return nil, fmt.Errorf("sequence discontinuity at entry %d: expected seq %d, got %d", expectedSeq, expectedSeq, rec.Seq)
		}

		// 2. Verify previous hash pointer
		if expectedSeq == 0 {
			firstPrevHash = rec.PrevRecordHash
		} else {
			if rec.PrevRecordHash != expectedPrevHash {
				return nil, fmt.Errorf("hash chain broken at seq %d: prev hash %s != expected %s",
					rec.Seq, rec.PrevRecordHash, expectedPrevHash)
			}
		}

		// 3. Recompute cryptographic hash
		computed := ComputeRecordHash(
			rec.PrevRecordHash,
			rec.Seq,
			rec.Timestamp,
			rec.ResourceID,
			rec.State,
			rec.RunbookID,
			rec.PayloadDigest,
		)

		if computed != rec.RecordHash {
			return nil, fmt.Errorf("tamper detected at seq %d: computed %s != recorded %s",
				rec.Seq, computed, rec.RecordHash)
		}

		expectedPrevHash = rec.RecordHash
		lastHash = rec.RecordHash
		expectedSeq++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error during ledger verification: %w", err)
	}

	return &VerificationResult{
		Valid:        true,
		TotalRecords: expectedSeq,
		GenesisHash:  firstPrevHash,
		TailHash:     lastHash,
		VerifiedAt:   time.Now().UTC(),
	}, nil
}
