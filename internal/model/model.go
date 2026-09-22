package model

import (
	"context"
	"syscall"
	"time"
)

// Severity represents the alert severity level.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Alert represents an incoming verified operational incident alert.
type Alert struct {
	ID            string            `json:"id"`
	Fingerprint   string            `json:"fingerprint"`
	Source        string            `json:"source"`
	ResourceID    string            `json:"resource_id"`
	Severity      Severity          `json:"severity"`
	Labels        map[string]string `json:"labels"`
	Annotations   map[string]string `json:"annotations"`
	ReceivedAt    time.Time         `json:"received_at"`
	HMACSignature string            `json:"hmac_signature,omitempty"`
	RawPayload    string            `json:"raw_payload,omitempty"`
}

// BlastRadius defines the physical and operational boundaries of a remediation action.
type BlastRadius struct {
	MaxExecutionTime     time.Duration `json:"max_execution_time"`
	MaxBytesMutated      int64         `json:"max_bytes_mutated"`
	MaxProcessesSignaled int           `json:"max_processes_signaled"`
	MaxFilesModified     int           `json:"max_files_modified"`
	AllowedPathPrefixes  []string      `json:"allowed_path_prefixes"`
}

// ConditionType denotes the deterministic check mechanism.
type ConditionType string

const (
	ConditionDiskFree     ConditionType = "disk_free_pct"
	ConditionProcessAlive ConditionType = "process_alive"
	ConditionHTTPHealth   ConditionType = "http_health"
	ConditionFileExists   ConditionType = "file_exists"
	ConditionCustom       ConditionType = "custom"
)

// Precondition represents a ground-truth check that must evaluate to true before mutation.
type Precondition struct {
	Name           string                                     `json:"name"`
	Type           ConditionType                              `json:"type"`
	Target         string                                     `json:"target"` // filesystem path, url, or identifier
	MinFreePct     float64                                    `json:"min_free_pct,omitempty"`
	ExpectedStatus int                                        `json:"expected_status,omitempty"`
	Timeout        time.Duration                              `json:"timeout,omitempty"`
	PID            int                                        `json:"pid,omitempty"`
	CheckFn        func(ctx context.Context) (bool, error)    `json:"-"`
}

// Postcondition represents a ground-truth check that must evaluate to true after mutation.
type Postcondition struct {
	Name           string                                     `json:"name"`
	Type           ConditionType                              `json:"type"`
	Target         string                                     `json:"target"`
	MinFreePct     float64                                    `json:"min_free_pct,omitempty"`
	ExpectedStatus int                                        `json:"expected_status,omitempty"`
	Timeout        time.Duration                              `json:"timeout,omitempty"`
	PID            int                                        `json:"pid,omitempty"`
	CheckFn        func(ctx context.Context) (bool, error)    `json:"-"`
}

// Action represents a sandboxed execution step.
type Action struct {
	Name             string                                                 `json:"name"`
	Binary           string                                                 `json:"binary,omitempty"`
	Args             []string                                               `json:"args,omitempty"`
	Timeout          time.Duration                                          `json:"timeout,omitempty"`
	UID              uint32                                                 `json:"uid,omitempty"`
	GID              uint32                                                 `json:"gid,omitempty"`
	TargetPID        int                                                    `json:"target_pid,omitempty"`
	Signal           syscall.Signal                                         `json:"signal,omitempty"`
	MutateFn         func(ctx context.Context) (*ExecutionResult, error)    `json:"-"`
}

// RollbackStep represents a single compensating step to be executed in reverse order.
type RollbackStep struct {
	Name             string                               `json:"name"`
	Binary           string                               `json:"binary,omitempty"`
	Args             []string                             `json:"args,omitempty"`
	TargetPath       string                               `json:"target_path,omitempty"`
	StagedBackupPath string                               `json:"staged_backup_path,omitempty"`
	CompensatingFn   func(ctx context.Context) error      `json:"-"`
}

// Runbook defines a declarative, deterministic remediation plan.
type Runbook struct {
	ID                string          `json:"id"`
	Version           string          `json:"version"`
	Name              string          `json:"name"`
	TargetResourceID  string          `json:"target_resource_id"`
	Severity          Severity        `json:"severity"`
	Preconditions     []Precondition  `json:"preconditions"`
	Actions           []Action        `json:"actions"`
	Postconditions    []Postcondition `json:"postconditions"`
	RollbackSteps     []RollbackStep  `json:"rollback_steps"`
	BlastRadius       BlastRadius     `json:"blast_radius"`
	MaxDampingPerHour int             `json:"max_damping_per_hour,omitempty"`
	Cooldown          time.Duration   `json:"cooldown,omitempty"`
}

// TargetResource returns the runbook's target resource identifier.
func (r *Runbook) TargetResource() string {
	if r == nil {
		return ""
	}
	return r.TargetResourceID
}

// ExecutionResult captures the output, metrics, and exit status of an action.
type ExecutionResult struct {
	ExitCode     int           `json:"exit_code"`
	Stdout       string        `json:"stdout"`
	Stderr       string        `json:"stderr"`
	Duration     time.Duration `json:"duration"`
	BytesMutated int64         `json:"bytes_mutated"`
	Success      bool          `json:"success"`
	Error        string        `json:"error,omitempty"`
}
