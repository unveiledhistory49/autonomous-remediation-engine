package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"autonomous-remediation-engine/internal/audit"
	"autonomous-remediation-engine/internal/damping"
	"autonomous-remediation-engine/internal/executor"
	"autonomous-remediation-engine/internal/lock"
	"autonomous-remediation-engine/internal/model"
	"autonomous-remediation-engine/internal/rollback"
	"autonomous-remediation-engine/internal/verifier"
)

var (
	ErrRunbookNotFound   = errors.New("matching runbook not found")
	ErrPreconditionFail  = errors.New("precondition invariant check failed")
	ErrPostconditionFail = errors.New("postcondition invariant check failed")
	ErrActionFailed      = errors.New("remediation action execution failed")
	ErrLockFailed        = errors.New("failed to acquire resource advisory lock")
)

// EngineConfig provides configuration options for the Autonomous Remediation Engine.
type EngineConfig struct {
	LockDir          string
	AuditLogPath     string
	JournalDir       string
	HostUUID         string
	DampingStatePath string
}

// RemediationResult encapsulates the outcome and telemetry of an end-to-end remediation run.
type RemediationResult struct {
	TxID         string                `json:"txid"`
	RunbookID    string                `json:"runbook_id"`
	ResourceID   string                `json:"resource_id"`
	FinalState   model.ExecutionState  `json:"final_state"`
	Success      bool                  `json:"success"`
	RolledBack   bool                  `json:"rolled_back"`
	ExecutionRes *model.ExecutionResult `json:"execution_result,omitempty"`
	Duration     time.Duration         `json:"duration"`
	Transitions  []model.StateTransition `json:"transitions"`
	Error        string                `json:"error,omitempty"`
}

// Engine implements the closed-loop control loop for autonomous remediation.
type Engine struct {
	cfg            EngineConfig
	mu             sync.RWMutex
	runbooks       map[string]*model.Runbook
	lockCoord      *lock.Coordinator
	ledger         *audit.Ledger
	journal        *rollback.Journal
	rollbackEngine *rollback.RollbackEngine
	executor       *executor.Executor
	damping        *damping.Controller
}

// NewEngine constructs and initializes all subsystems of the remediation engine.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	lockCoord, err := lock.NewCoordinator(cfg.LockDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize lock coordinator: %w", err)
	}

	ledger, err := audit.NewLedger(cfg.AuditLogPath, cfg.HostUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize audit ledger: %w", err)
	}

	journal, err := rollback.NewJournal(cfg.JournalDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WAL journal: %w", err)
	}

	dampingCtrl, err := damping.NewController(cfg.DampingStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize damping controller: %w", err)
	}

	rbEngine := rollback.NewRollbackEngine(journal)
	exec := executor.NewExecutor()

	return &Engine{
		cfg:            cfg,
		runbooks:       make(map[string]*model.Runbook),
		lockCoord:      lockCoord,
		ledger:         ledger,
		journal:        journal,
		rollbackEngine: rbEngine,
		executor:       exec,
		damping:        dampingCtrl,
	}, nil
}

// ProcessAlert processes an incoming alert with background context.
func (e *Engine) ProcessAlert(alert *model.Alert) (*RemediationResult, error) {
	return e.Remediate(context.Background(), alert)
}

// ProcessAlertContext processes an incoming alert with the provided context.
func (e *Engine) ProcessAlertContext(ctx context.Context, alert *model.Alert) (*RemediationResult, error) {
	return e.Remediate(ctx, alert)
}

// Ledger returns the engine's cryptographic audit ledger.
func (e *Engine) Ledger() *audit.Ledger {
	return e.ledger
}

// LockCoordinator returns the engine's resource lock coordinator.
func (e *Engine) LockCoordinator() *lock.Coordinator {
	return e.lockCoord
}

// Journal returns the engine's rollback journal.
func (e *Engine) Journal() *rollback.Journal {
	return e.journal
}

// Config returns the engine's configuration.
func (e *Engine) Config() EngineConfig {
	return e.cfg
}

// IsHealthy evaluates whether critical engine subsystems (lock dir, audit ledger) are operational.
func (e *Engine) IsHealthy() (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.ledger == nil {
		return false, "audit ledger is not active"
	}

	if e.cfg.LockDir != "" {
		if err := os.MkdirAll(e.cfg.LockDir, 0755); err != nil {
			return false, fmt.Sprintf("lock directory %s cannot be created: %v", e.cfg.LockDir, err)
		}
		testFile := filepath.Join(e.cfg.LockDir, fmt.Sprintf(".healthcheck-%d", time.Now().UnixNano()))
		if err := os.WriteFile(testFile, []byte("healthcheck"), 0600); err != nil {
			return false, fmt.Sprintf("lock directory %s is not writable: %v", e.cfg.LockDir, err)
		}
		_ = os.Remove(testFile)
	}

	return true, "healthy"
}

// Damping returns the engine's flapping damping controller.
func (e *Engine) Damping() *damping.Controller {
	return e.damping
}

// RegisterRunbook adds or updates a declarative runbook in the engine catalog.
func (e *Engine) RegisterRunbook(rb *model.Runbook) error {
	if rb == nil || rb.ID == "" {
		return errors.New("cannot register nil or un-identified runbook")
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.runbooks[rb.ID] = rb
	return nil
}

// GetRunbook retrieves a runbook from the engine catalog by ID, Name, or canonical alias.
func (e *Engine) GetRunbook(id string) (*model.Runbook, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if rb, ok := e.runbooks[id]; ok {
		return rb, nil
	}
	for _, rb := range e.runbooks {
		if rb.Name == id || rb.ID == id {
			return rb, nil
		}
	}

	// Standard alias mapping
	var canonID string
	switch id {
	case "disk_cleanup_var_log", "disk_log_drain", "RBK-DISK-001":
		canonID = "RBK-DISK-001"
	case "service_deadlock_restart", "service_hang_recovery", "RBK-PROC-001":
		canonID = "RBK-PROC-001"
	case "tls_cert_renew_internal", "tls_cert_rotation", "tls_cert_reload", "RBK-TLS-001":
		canonID = "RBK-TLS-001"
	case "config_rollback", "RBK-CFG-001":
		canonID = "RBK-CFG-001"
	}
	if canonID != "" {
		if rb, ok := e.runbooks[canonID]; ok {
			return rb, nil
		}
		for _, rb := range e.runbooks {
			if rb.ID == canonID || rb.Name == canonID {
				return rb, nil
			}
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrRunbookNotFound, id)
}

// ListRunbooks returns all registered runbooks in the engine.
func (e *Engine) ListRunbooks() []*model.Runbook {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]*model.Runbook, 0, len(e.runbooks))
	for _, rb := range e.runbooks {
		list = append(list, rb)
	}
	return list
}

// Close gracefully flushes and shuts down engine persistence subsystems.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.ledger != nil {
		return e.ledger.Close()
	}
	return nil
}

// RunDirect initiates a remediation workflow for a given runbook ID and resource target directly.
func (e *Engine) RunDirect(ctx context.Context, runbookID, resourceID string) (*RemediationResult, error) {
	rb, err := e.GetRunbook(runbookID)
	if err != nil {
		return nil, err
	}

	alert := &model.Alert{
		ID:          fmt.Sprintf("manual-%d", time.Now().UnixNano()),
		Fingerprint: fmt.Sprintf("fp-%s-%s", runbookID, resourceID),
		Source:      "remediation-ctl",
		ResourceID:  resourceID,
		Severity:    rb.Severity,
		Labels: map[string]string{
			"runbook_id": runbookID,
		},
		ReceivedAt: time.Now().UTC(),
	}

	return e.Remediate(ctx, alert)
}

// Remediate executes the complete 11-state closed-loop remediation control loop.
func (e *Engine) Remediate(ctx context.Context, alert *model.Alert) (*RemediationResult, error) {
	start := time.Now()

	if alert != nil && alert.ResourceID != "" {
		ctx = context.WithValue(ctx, model.TargetResourceContextKey, alert.ResourceID)
	}

	// 1. Initialize FSM: DETECTED
	fsm, err := model.NewFSM(model.StateDetected)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize FSM: %w", err)
	}

	if alert == nil || alert.ID == "" || alert.ResourceID == "" {
		_ = fsm.Transition(model.StateEscalated, "malformed or empty alert")
		return &RemediationResult{
			FinalState:  model.StateEscalated,
			Duration:    time.Since(start),
			Transitions: fsm.History(),
			Error:       "malformed alert payload",
		}, errors.New("malformed or empty alert")
	}

	rawAlertJSON, _ := json.Marshal(alert)
	baseDigest := audit.ComputePayloadDigest(string(rawAlertJSON), "", "")

	// Append DETECTED
	_, _ = e.ledger.Append(alert.ResourceID, "", model.StateDetected, baseDigest)

	// 2. Runbook Resolution: EVALUATING
	runbookID := alert.Labels["runbook_id"]
	var matchedRunbook *model.Runbook
	if runbookID != "" {
		matchedRunbook, _ = e.GetRunbook(runbookID)
	} else {
		// Attempt match by target resource
		e.mu.RLock()
		for _, rb := range e.runbooks {
			if rb.TargetResourceID == alert.ResourceID {
				matchedRunbook = rb
				break
			}
		}
		e.mu.RUnlock()
	}

	if matchedRunbook == nil {
		_ = fsm.Transition(model.StateEscalated, "no runbook matched for resource "+alert.ResourceID)
		_, _ = e.ledger.Append(alert.ResourceID, "", model.StateEscalated, baseDigest)
		return &RemediationResult{
			ResourceID:  alert.ResourceID,
			FinalState:  model.StateEscalated,
			Duration:    time.Since(start),
			Transitions: fsm.History(),
			Error:       "no matching runbook found",
		}, ErrRunbookNotFound
	}

	_ = fsm.Transition(model.StateEvaluating, "matched runbook "+matchedRunbook.ID)
	_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateEvaluating, baseDigest)

	// 3. Acquire Resource Advisory Lock (Mutual Exclusion)
	resLock, err := e.lockCoord.TryLock(alert.ResourceID)
	if err != nil {
		failReason := fmt.Sprintf("resource lock collision on %s: %v", alert.ResourceID, err)
		_ = fsm.Transition(model.StatePrecheckFailed, failReason)
		_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StatePrecheckFailed, baseDigest)

		_ = fsm.Transition(model.StateEscalated, "resource locked; escalation required")
		_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateEscalated, baseDigest)

		return &RemediationResult{
			RunbookID:   matchedRunbook.ID,
			ResourceID:  alert.ResourceID,
			FinalState:  model.StateEscalated,
			Duration:    time.Since(start),
			Transitions: fsm.History(),
			Error:       failReason,
		}, ErrLockFailed
	}
	defer resLock.Unlock()

	// 4. Evaluate Flap Damping Gate
	targetResource := matchedRunbook.TargetResource()
	if targetResource == "" {
		targetResource = alert.ResourceID
	}

	canExec, dampReason := e.damping.CanExecute(targetResource)
	if !canExec {
		failReason := fmt.Sprintf("FLAP_DAMPING_BREACH: %s", dampReason)
		_ = fsm.Transition(model.StatePrecheckFailed, failReason)
		_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StatePrecheckFailed, baseDigest)

		_ = fsm.Transition(model.StateEscalated, "flap damping breach; fail-closed")
		_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateEscalated, baseDigest)

		return &RemediationResult{
			RunbookID:   matchedRunbook.ID,
			ResourceID:  alert.ResourceID,
			FinalState:  model.StatePrecheckFailed,
			Duration:    time.Since(start),
			Transitions: fsm.History(),
			Error:       failReason,
		}, fmt.Errorf("%w: %s", ErrPreconditionFail, failReason)
	}

	// 5. Assert Deterministic Preconditions
	for _, pre := range matchedRunbook.Preconditions {
		ok, preErr := verifier.VerifyPrecondition(ctx, pre)
		if !ok || preErr != nil {
			msg := fmt.Sprintf("precondition %q failed: %v", pre.Name, preErr)
			_ = fsm.Transition(model.StatePrecheckFailed, msg)
			_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StatePrecheckFailed, baseDigest)

			_ = fsm.Transition(model.StateEscalated, "precheck failed; fail-closed")
			_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateEscalated, baseDigest)

			return &RemediationResult{
				RunbookID:   matchedRunbook.ID,
				ResourceID:  alert.ResourceID,
				FinalState:  model.StatePrecheckFailed,
				Duration:    time.Since(start),
				Transitions: fsm.History(),
				Error:       msg,
			}, fmt.Errorf("%w: %s", ErrPreconditionFail, msg)
		}
	}

	_ = fsm.Transition(model.StatePrecheckPassed, "all preconditions verified")
	_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StatePrecheckPassed, baseDigest)

	// 6. Stage Compensating Actions to WAL before any mutation occurs
	txID := fmt.Sprintf("%s-%s-%d", matchedRunbook.ID, alert.ID, time.Now().UnixNano())
	walRec, err := e.journal.Stage(txID, matchedRunbook.ID, alert.ResourceID, matchedRunbook.RollbackSteps)
	if err != nil {
		msg := fmt.Sprintf("failed to stage WAL record: %v", err)
		_ = fsm.Transition(model.StateEscalated, msg)
		_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateEscalated, baseDigest)

		return &RemediationResult{
			TxID:        txID,
			RunbookID:   matchedRunbook.ID,
			ResourceID:  alert.ResourceID,
			FinalState:  model.StateEscalated,
			Duration:    time.Since(start),
			Transitions: fsm.History(),
			Error:       msg,
		}, err
	}

	// 7. Transition to EXECUTING and dispatch mutations
	_ = fsm.Transition(model.StateExecuting, "executing mutation actions")
	_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateExecuting, baseDigest)

	var lastExecRes *model.ExecutionResult
	var actionFailed bool
	var failureReason string

	for _, act := range matchedRunbook.Actions {
		res, actErr := e.executor.Execute(ctx, act, matchedRunbook.BlastRadius)
		lastExecRes = res
		if actErr != nil || (res != nil && !res.Success) {
			actionFailed = true
			if actErr != nil {
				failureReason = fmt.Sprintf("action %s error: %v", act.Name, actErr)
			} else {
				failureReason = fmt.Sprintf("action %s failed: %s", act.Name, res.Error)
			}
			break
		}
	}

	// 8. Verify Postconditions if action execution completed
	var postconditionFailed bool
	if !actionFailed {
		for _, post := range matchedRunbook.Postconditions {
			ok, postErr := verifier.VerifyPostcondition(ctx, post)
			if !ok || postErr != nil {
				postconditionFailed = true
				failureReason = fmt.Sprintf("postcondition %q unmet: %v", post.Name, postErr)
				break
			}
		}
	}

	// 9. Outcome Branching:
	var stdout, stderr string
	if lastExecRes != nil {
		stdout = lastExecRes.Stdout
		stderr = lastExecRes.Stderr
	}
	execDigest := audit.ComputePayloadDigest(string(rawAlertJSON), stdout, stderr)

	// Happy Path: actions succeeded and postconditions verified
	if !actionFailed && !postconditionFailed {
		_ = fsm.Transition(model.StatePostcheckPassed, "ground-truth postconditions verified")
		_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StatePostcheckPassed, execDigest)

		_ = fsm.Transition(model.StateCommitted, "remediation successfully verified and committed")
		_ = e.journal.UpdateState(txID, rollback.StateCommitted)
		_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateCommitted, execDigest)

		// Record successful execution for rate damping
		e.damping.RecordExecution(targetResource)

		return &RemediationResult{
			TxID:         txID,
			RunbookID:    matchedRunbook.ID,
			ResourceID:   alert.ResourceID,
			FinalState:   model.StateCommitted,
			Success:      true,
			RolledBack:   false,
			ExecutionRes: lastExecRes,
			Duration:     time.Since(start),
			Transitions:  fsm.History(),
		}, nil
	}

	// Fault Path: action failure or postcondition failure -> Automated Rollback
	_ = fsm.Transition(model.StatePostcheckFailed, failureReason)
	_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StatePostcheckFailed, execDigest)

	_ = fsm.Transition(model.StateRollingBack, "initiating compensating rollback actions")
	_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateRollingBack, execDigest)

	rbErr := e.rollbackEngine.ExecuteRollback(ctx, walRec)
	if rbErr != nil {
		// Rollback failed! Immediate Sev-1 escalation
		escalateMsg := fmt.Sprintf("automated rollback failed: %v (initial fault: %s)", rbErr, failureReason)
		_ = fsm.Transition(model.StateEscalated, escalateMsg)
		_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateEscalated, execDigest)

		return &RemediationResult{
			TxID:         txID,
			RunbookID:    matchedRunbook.ID,
			ResourceID:   alert.ResourceID,
			FinalState:   model.StateEscalated,
			Success:      false,
			RolledBack:   false,
			ExecutionRes: lastExecRes,
			Duration:     time.Since(start),
			Transitions:  fsm.History(),
			Error:        escalateMsg,
		}, fmt.Errorf("remediation failed and rollback faulted: %w", rbErr)
	}

	// Rollback completed cleanly
	_ = fsm.Transition(model.StateRolledBack, "compensating actions executed cleanly")
	_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateRolledBack, execDigest)

	// Monotonic transition to ESCALATED since original root cause is unverified/unresolved
	_ = fsm.Transition(model.StateEscalated, "remediation rolled back; escalating to operator")
	_, _ = e.ledger.Append(alert.ResourceID, matchedRunbook.ID, model.StateEscalated, execDigest)

	return &RemediationResult{
		TxID:         txID,
		RunbookID:    matchedRunbook.ID,
		ResourceID:   alert.ResourceID,
		FinalState:   model.StateRolledBack,
		Success:      false,
		RolledBack:   true,
		ExecutionRes: lastExecRes,
		Duration:     time.Since(start),
		Transitions:  fsm.History(),
		Error:        failureReason,
	}, fmt.Errorf("%w: %s", ErrPostconditionFail, failureReason)
}
