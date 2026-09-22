package model

import (
	"sync"
	"testing"
)

func TestFSM_HappyPath(t *testing.T) {
	fsm, err := NewFSM(StateDetected)
	if err != nil {
		t.Fatalf("failed to create FSM: %v", err)
	}

	transitions := []struct {
		target ExecutionState
		reason string
	}{
		{StateEvaluating, "matched runbook RBK-001"},
		{StatePrecheckPassed, "preconditions and blast radius verified"},
		{StateExecuting, "spawned child process"},
		{StatePostcheckPassed, "postcondition verified healthy"},
		{StateCommitted, "ledger entry committed"},
	}

	for _, step := range transitions {
		if err := fsm.Transition(step.target, step.reason); err != nil {
			t.Fatalf("expected successful transition to %s, got: %v", step.target, err)
		}
		if fsm.Current() != step.target {
			t.Fatalf("expected current state %s, got %s", step.target, fsm.Current())
		}
	}

	if !fsm.IsTerminal() {
		t.Fatalf("expected COMMITTED to be terminal")
	}

	history := fsm.History()
	if len(history) != 6 { // 1 init + 5 transitions
		t.Fatalf("expected 6 history items, got %d", len(history))
	}
}

func TestFSM_PrecheckFailedPath(t *testing.T) {
	fsm, err := NewFSM(StateDetected)
	if err != nil {
		t.Fatalf("failed to create FSM: %v", err)
	}

	if err := fsm.Transition(StateEvaluating, "matched"); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if err := fsm.Transition(StatePrecheckFailed, "disk space is already sufficient"); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if err := fsm.Transition(StateEscalated, "alert discarded, operator notified"); err != nil {
		t.Fatalf("failed: %v", err)
	}

	if !fsm.IsTerminal() {
		t.Fatalf("expected ESCALATED to be terminal")
	}
}

func TestFSM_PostcheckFailedAndRollback(t *testing.T) {
	fsm, err := NewFSM(StateDetected)
	if err != nil {
		t.Fatalf("failed to create FSM: %v", err)
	}

	steps := []ExecutionState{
		StateEvaluating,
		StatePrecheckPassed,
		StateExecuting,
		StatePostcheckFailed,
		StateRollingBack,
		StateRolledBack,
		StateEscalated,
	}

	for _, s := range steps {
		if err := fsm.Transition(s, "testing transition"); err != nil {
			t.Fatalf("transition to %s failed: %v", s, err)
		}
	}

	if fsm.Current() != StateEscalated {
		t.Fatalf("expected current state %s, got %s", StateEscalated, fsm.Current())
	}
}

func TestFSM_RollbackToEscalatedDirectly(t *testing.T) {
	fsm, err := NewFSM(StateDetected)
	if err != nil {
		t.Fatalf("failed to create FSM: %v", err)
	}

	steps := []ExecutionState{
		StateEvaluating,
		StatePrecheckPassed,
		StateExecuting,
		StatePostcheckFailed,
		StateRollingBack,
		StateEscalated,
	}

	for _, s := range steps {
		if err := fsm.Transition(s, "testing direct rollback escalation"); err != nil {
			t.Fatalf("transition to %s failed: %v", s, err)
		}
	}

	if fsm.Current() != StateEscalated {
		t.Fatalf("expected current state %s, got %s", StateEscalated, fsm.Current())
	}
}

func TestFSM_DetectedToEscalatedDirectly(t *testing.T) {
	fsm, err := NewFSM(StateDetected)
	if err != nil {
		t.Fatalf("failed to create FSM: %v", err)
	}

	if err := fsm.Transition(StateEscalated, "unmatched alert / signature invalid"); err != nil {
		t.Fatalf("expected direct escalation from DETECTED, got error: %v", err)
	}

	if fsm.Current() != StateEscalated {
		t.Fatalf("expected ESCALATED, got %s", fsm.Current())
	}
}

func TestFSM_IllegalTransitions(t *testing.T) {
	illegalPairs := []struct {
		from ExecutionState
		to   ExecutionState
	}{
		{StateDetected, StateExecuting},
		{StateDetected, StateCommitted},
		{StateEvaluating, StateCommitted},
		{StateEvaluating, StateExecuting},
		{StatePrecheckPassed, StateCommitted},
		{StatePrecheckPassed, StateRollingBack},
		{StateExecuting, StateCommitted},
		{StateExecuting, StateRolledBack},
		{StateCommitted, StateDetected},
		{StateCommitted, StateExecuting},
		{StateEscalated, StateDetected},
		{StatePostcheckPassed, StateRollingBack},
	}

	for _, pair := range illegalPairs {
		fsm, err := NewFSM(pair.from)
		if err != nil {
			t.Fatalf("failed to create FSM at state %s: %v", pair.from, err)
		}
		if err := fsm.Transition(pair.to, "illegal test"); err == nil {
			t.Errorf("expected error transitioning from %s to %s, but succeeded", pair.from, pair.to)
		}
	}
}

func TestFSM_InvalidState(t *testing.T) {
	if _, err := NewFSM(ExecutionState("NON_EXISTENT")); err == nil {
		t.Fatalf("expected error creating FSM with non-existent state")
	}

	fsm, _ := NewFSM(StateDetected)
	if err := fsm.Transition(ExecutionState("BOGUS"), "test"); err == nil {
		t.Fatalf("expected error transitioning to bogus state")
	}
}

func TestFSM_Concurrency(t *testing.T) {
	fsm, err := NewFSM(StateDetected)
	if err != nil {
		t.Fatalf("failed to create FSM: %v", err)
	}

	var wg sync.WaitGroup
	// 50 concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = fsm.Current()
			_ = fsm.History()
			_ = fsm.IsTerminal()
		}()
	}
	wg.Wait()
}
