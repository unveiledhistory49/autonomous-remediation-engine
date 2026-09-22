package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"autonomous-remediation-engine/internal/audit"
	"autonomous-remediation-engine/internal/model"
)

func setupTestEngine(t *testing.T) (*Engine, string, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "engine-e2e-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	cfg := EngineConfig{
		LockDir:      filepath.Join(tempDir, "locks"),
		AuditLogPath: filepath.Join(tempDir, "audit.log"),
		JournalDir:   filepath.Join(tempDir, "journal"),
		HostUUID:     "test-host-arm64",
	}

	eng, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	cleanup := func() {
		_ = eng.Close()
		_ = os.RemoveAll(tempDir)
	}

	return eng, cfg.AuditLogPath, cleanup
}

func TestEngine_HappyPath(t *testing.T) {
	eng, auditPath, cleanup := setupTestEngine(t)
	defer cleanup()

	var actionExecuted bool
	var postchecked bool

	rb := &model.Runbook{
		ID:               "RBK-HAPPY-001",
		TargetResourceID: "/var/log/test-service",
		Severity:         model.SeverityHigh,
		Preconditions: []model.Precondition{
			{
				Name: "pre-always-true",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					return true, nil
				},
			},
		},
		Actions: []model.Action{
			{
				Name: "clean-logs",
				MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
					actionExecuted = true
					return &model.ExecutionResult{
						Success:      true,
						BytesMutated: 1024,
						Stdout:       "1024 bytes purged",
					}, nil
				},
			},
		},
		Postconditions: []model.Postcondition{
			{
				Name: "post-always-true",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					postchecked = true
					return true, nil
				},
			},
		},
		BlastRadius: model.BlastRadius{
			MaxExecutionTime: 5 * time.Second,
			MaxBytesMutated:  10000,
		},
	}

	if err := eng.RegisterRunbook(rb); err != nil {
		t.Fatalf("failed to register runbook: %v", err)
	}

	alert := &model.Alert{
		ID:          "alert-happy-1",
		Fingerprint: "fp-happy",
		Source:      "test",
		ResourceID:  "/var/log/test-service",
		Severity:    model.SeverityHigh,
		Labels: map[string]string{
			"runbook_id": "RBK-HAPPY-001",
		},
		ReceivedAt: time.Now().UTC(),
	}

	ctx := context.Background()
	res, err := eng.Remediate(ctx, alert)
	if err != nil {
		t.Fatalf("remediation failed unexpectedly: %v", err)
	}

	if !res.Success {
		t.Fatalf("expected res.Success == true")
	}

	if res.FinalState != model.StateCommitted {
		t.Fatalf("expected final state COMMITTED, got %s", res.FinalState)
	}

	if !actionExecuted {
		t.Fatalf("expected action to be executed")
	}

	if !postchecked {
		t.Fatalf("expected postcondition to be evaluated")
	}

	// Verify Audit Ledger cryptographically
	report, err := audit.VerifyLedgerFile(auditPath)
	if err != nil {
		t.Fatalf("audit verification failed: %v", err)
	}
	if !report.Valid {
		t.Fatalf("audit ledger is not valid")
	}
	if report.TotalRecords != 6 { // DETECTED, EVALUATING, PRECHECK_PASSED, EXECUTING, POSTCHECK_PASSED, COMMITTED
		t.Fatalf("expected 6 audit records, got %d", report.TotalRecords)
	}
}

func TestEngine_PreconditionFailure(t *testing.T) {
	eng, auditPath, cleanup := setupTestEngine(t)
	defer cleanup()

	var mutationExecuted bool

	rb := &model.Runbook{
		ID:               "RBK-PREFAIL-001",
		TargetResourceID: "/var/data/disk",
		Severity:         model.SeverityMedium,
		Preconditions: []model.Precondition{
			{
				Name: "pre-must-fail",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					// Precondition reports false (e.g. disk space is not low)
					return false, errors.New("disk space threshold not met")
				},
			},
		},
		Actions: []model.Action{
			{
				Name: "forbidden-mutation",
				MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
					mutationExecuted = true
					return &model.ExecutionResult{Success: true}, nil
				},
			},
		},
		BlastRadius: model.BlastRadius{
			MaxExecutionTime: 5 * time.Second,
		},
	}

	_ = eng.RegisterRunbook(rb)

	alert := &model.Alert{
		ID:         "alert-pre-fail",
		ResourceID: "/var/data/disk",
		Severity:   model.SeverityMedium,
		Labels: map[string]string{
			"runbook_id": "RBK-PREFAIL-001",
		},
		ReceivedAt: time.Now().UTC(),
	}

	ctx := context.Background()
	res, err := eng.Remediate(ctx, alert)
	if err == nil {
		t.Fatalf("expected error from failed precondition, got nil")
	}

	if !errors.Is(err, ErrPreconditionFail) {
		t.Fatalf("expected ErrPreconditionFail, got: %v", err)
	}

	if mutationExecuted {
		t.Fatalf("CRITICAL: mutation was executed despite precondition failure!")
	}

	if res.FinalState != model.StatePrecheckFailed {
		t.Fatalf("expected state PRECHECK_FAILED, got %s", res.FinalState)
	}

	// Verify Audit Ledger
	report, err := audit.VerifyLedgerFile(auditPath)
	if err != nil {
		t.Fatalf("audit verification failed: %v", err)
	}
	if !report.Valid {
		t.Fatalf("audit ledger is not valid")
	}
}

func TestEngine_PostconditionFailureAndRollback(t *testing.T) {
	eng, auditPath, cleanup := setupTestEngine(t)
	defer cleanup()

	var actionExecuted bool
	var rollbackExecuted bool

	rb := &model.Runbook{
		ID:               "RBK-POSTFAIL-001",
		TargetResourceID: "/etc/service/config",
		Severity:         model.SeverityCritical,
		Preconditions: []model.Precondition{
			{
				Name: "pre-ok",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					return true, nil
				},
			},
		},
		Actions: []model.Action{
			{
				Name: "apply-config",
				MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
					actionExecuted = true
					return &model.ExecutionResult{Success: true, BytesMutated: 120}, nil
				},
			},
		},
		Postconditions: []model.Postcondition{
			{
				Name: "post-health-fails",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					// Postcondition verification fails!
					return false, errors.New("service daemon crashed on new config")
				},
			},
		},
		RollbackSteps: []model.RollbackStep{
			{
				Name: "restore-lkg-config",
				CompensatingFn: func(ctx context.Context) error {
					rollbackExecuted = true
					return nil
				},
			},
		},
		BlastRadius: model.BlastRadius{
			MaxExecutionTime: 5 * time.Second,
			MaxBytesMutated:  1000,
		},
	}

	_ = eng.RegisterRunbook(rb)

	alert := &model.Alert{
		ID:         "alert-post-fail",
		ResourceID: "/etc/service/config",
		Severity:   model.SeverityCritical,
		Labels: map[string]string{
			"runbook_id": "RBK-POSTFAIL-001",
		},
		ReceivedAt: time.Now().UTC(),
	}

	ctx := context.Background()
	res, err := eng.Remediate(ctx, alert)
	if err == nil {
		t.Fatalf("expected error from failed postcondition, got nil")
	}

	if !errors.Is(err, ErrPostconditionFail) {
		t.Fatalf("expected ErrPostconditionFail, got: %v", err)
	}

	if !actionExecuted {
		t.Fatalf("expected action to have executed")
	}

	if !rollbackExecuted {
		t.Fatalf("expected compensating rollback to have executed!")
	}

	if !res.RolledBack {
		t.Fatalf("expected res.RolledBack == true")
	}

	if res.FinalState != model.StateRolledBack {
		t.Fatalf("expected final state ROLLED_BACK, got %s", res.FinalState)
	}

	// Verify Audit Ledger
	report, err := audit.VerifyLedgerFile(auditPath)
	if err != nil {
		t.Fatalf("audit verification failed: %v", err)
	}
	if !report.Valid {
		t.Fatalf("audit ledger is not valid")
	}

	// States recorded should include POSTCHECK_FAILED and ROLLED_BACK
	foundRolledBack := false
	for _, transition := range res.Transitions {
		if transition.To == model.StateRolledBack {
			foundRolledBack = true
		}
	}
	if !foundRolledBack {
		t.Fatalf("expected transition to ROLLED_BACK in history")
	}
}

func TestEngine_MutualExclusionLock(t *testing.T) {
	eng, _, cleanup := setupTestEngine(t)
	defer cleanup()

	barrier := make(chan struct{})
	unblock := make(chan struct{})

	rb := &model.Runbook{
		ID:               "RBK-CONCURRENT-001",
		TargetResourceID: "singleton-resource",
		Severity:         model.SeverityHigh,
		Preconditions: []model.Precondition{
			{
				Name: "pre-block",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					close(barrier)
					<-unblock
					return true, nil
				},
			},
		},
		Actions: []model.Action{
			{
				Name: "noop",
				MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
					return &model.ExecutionResult{Success: true}, nil
				},
			},
		},
		BlastRadius: model.BlastRadius{
			MaxExecutionTime: 5 * time.Second,
		},
	}
	_ = eng.RegisterRunbook(rb)

	var wg sync.WaitGroup
	var res1, res2 *RemediationResult
	var err1, err2 error

	// Worker 1 acquires lock and pauses in precheck
	wg.Add(1)
	go func() {
		defer wg.Done()
		res1, err1 = eng.RunDirect(context.Background(), "RBK-CONCURRENT-001", "singleton-resource")
	}()

	// Wait until Worker 1 holds the lock
	<-barrier

	// Worker 2 attempts concurrent remediation on same resource
	wg.Add(1)
	go func() {
		defer wg.Done()
		res2, err2 = eng.RunDirect(context.Background(), "RBK-CONCURRENT-001", "singleton-resource")
	}()

	// Give worker 2 time to hit the lock check
	time.Sleep(50 * time.Millisecond)

	// Unblock worker 1
	close(unblock)
	wg.Wait()

	if err1 != nil {
		t.Fatalf("worker 1 should have succeeded, got: %v", err1)
	}
	if !res1.Success {
		t.Fatalf("expected worker 1 success")
	}

	// Worker 2 should fail with lock collision
	if err2 == nil {
		t.Fatalf("expected worker 2 to fail with lock collision, but got nil")
	}
	if !errors.Is(err2, ErrLockFailed) {
		t.Fatalf("expected ErrLockFailed for worker 2, got: %v", err2)
	}
	if res2.FinalState != model.StateEscalated {
		t.Fatalf("expected worker 2 final state ESCALATED, got %s", res2.FinalState)
	}
}

func TestEngine_FlapDampingIntegration(t *testing.T) {
	eng, auditPath, cleanup := setupTestEngine(t)
	defer cleanup()

	baseTime := time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC)
	currentTime := baseTime
	eng.Damping().SetNowFunc(func() time.Time { return currentTime })

	var execCount int
	rb := &model.Runbook{
		ID:               "RBK-DAMP-001",
		TargetResourceID: "target-service-damping",
		Severity:         model.SeverityHigh,
		Preconditions: []model.Precondition{
			{
				Name: "pre-always-true",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					return true, nil
				},
			},
		},
		Actions: []model.Action{
			{
				Name: "damped-action",
				MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
					execCount++
					return &model.ExecutionResult{Success: true}, nil
				},
			},
		},
		Postconditions: []model.Postcondition{
			{
				Name: "post-always-true",
				Type: model.ConditionCustom,
				CheckFn: func(ctx context.Context) (bool, error) {
					return true, nil
				},
			},
		},
		BlastRadius: model.BlastRadius{
			MaxExecutionTime: 5 * time.Second,
		},
	}

	if err := eng.RegisterRunbook(rb); err != nil {
		t.Fatalf("failed to register runbook: %v", err)
	}

	ctx := context.Background()

	// 1. First execution should succeed and record execution
	res1, err := eng.RunDirect(ctx, "RBK-DAMP-001", "target-service-damping")
	if err != nil {
		t.Fatalf("first execution should succeed, got: %v", err)
	}
	if !res1.Success || res1.FinalState != model.StateCommitted {
		t.Fatalf("expected COMMITTED, got %s", res1.FinalState)
	}
	if execCount != 1 {
		t.Fatalf("expected execCount == 1, got %d", execCount)
	}

	// 2. Second execution 10 seconds later (cooldown violation: elapsed 10s < 300s)
	currentTime = baseTime.Add(10 * time.Second)
	res2, err := eng.RunDirect(ctx, "RBK-DAMP-001", "target-service-damping")
	if err == nil {
		t.Fatalf("expected second execution to fail due to flap damping, got nil")
	}
	if !errors.Is(err, ErrPreconditionFail) {
		t.Fatalf("expected ErrPreconditionFail, got: %v", err)
	}
	if res2.FinalState != model.StatePrecheckFailed {
		t.Fatalf("expected final state PRECHECK_FAILED, got %s", res2.FinalState)
	}
	if !strings.Contains(res2.Error, "FLAP_DAMPING_BREACH") {
		t.Fatalf("expected FLAP_DAMPING_BREACH in error, got: %s", res2.Error)
	}
	// Action must NOT have run
	if execCount != 1 {
		t.Fatalf("action must not execute when damping breached, execCount = %d", execCount)
	}

	// Verify Audit Ledger records FLAP_DAMPING_BREACH
	report, err := audit.VerifyLedgerFile(auditPath)
	if err != nil {
		t.Fatalf("audit verification failed: %v", err)
	}
	if !report.Valid {
		t.Fatalf("audit ledger is not valid")
	}

	// 3. Reset damping and verify execution succeeds again
	eng.Damping().Reset("target-service-damping")
	currentTime = baseTime.Add(350 * time.Second)
	res3, err := eng.RunDirect(ctx, "RBK-DAMP-001", "target-service-damping")
	if err != nil {
		t.Fatalf("execution after Reset should succeed, got: %v", err)
	}
	if !res3.Success || res3.FinalState != model.StateCommitted {
		t.Fatalf("expected COMMITTED after reset, got %s", res3.FinalState)
	}
	if execCount != 2 {
		t.Fatalf("expected execCount == 2 after reset run, got %d", execCount)
	}
}
