package model

import (
	"fmt"
	"sync"
	"time"
)

// ExecutionState represents the explicit 11-state remediation FSM.
type ExecutionState string

const (
	StateDetected        ExecutionState = "DETECTED"
	StateEvaluating      ExecutionState = "EVALUATING"
	StatePrecheckPassed  ExecutionState = "PRECHECK_PASSED"
	StatePrecheckFailed  ExecutionState = "PRECHECK_FAILED"
	StateExecuting       ExecutionState = "EXECUTING"
	StatePostcheckPassed ExecutionState = "POSTCHECK_PASSED"
	StateCommitted       ExecutionState = "COMMITTED"
	StatePostcheckFailed ExecutionState = "POSTCHECK_FAILED"
	StateRollingBack     ExecutionState = "ROLLING_BACK"
	StateRolledBack      ExecutionState = "ROLLED_BACK"
	StateEscalated       ExecutionState = "ESCALATED"
)

// AllStates provides the complete list of 11 FSM states.
var AllStates = []ExecutionState{
	StateDetected,
	StateEvaluating,
	StatePrecheckPassed,
	StatePrecheckFailed,
	StateExecuting,
	StatePostcheckPassed,
	StateCommitted,
	StatePostcheckFailed,
	StateRollingBack,
	StateRolledBack,
	StateEscalated,
}

// validTransitions defines the unidirectional, monotonic DAG transitions of the FSM.
var validTransitions = map[ExecutionState]map[ExecutionState]bool{
	StateDetected: {
		StateEvaluating: true,
		StateEscalated:  true,
	},
	StateEvaluating: {
		StatePrecheckPassed: true,
		StatePrecheckFailed: true,
	},
	StatePrecheckPassed: {
		StateExecuting: true,
	},
	StatePrecheckFailed: {
		StateEscalated: true,
	},
	StateExecuting: {
		StatePostcheckPassed: true,
		StatePostcheckFailed: true,
	},
	StatePostcheckPassed: {
		StateCommitted: true,
	},
	StatePostcheckFailed: {
		StateRollingBack: true,
	},
	StateRollingBack: {
		StateRolledBack: true,
		StateEscalated:  true,
	},
	StateRolledBack: {
		StateEscalated: true,
	},
	StateCommitted: {},
	StateEscalated: {},
}

// IsValidState returns true if s is one of the 11 defined FSM states.
func IsValidState(s ExecutionState) bool {
	for _, state := range AllStates {
		if state == s {
			return true
		}
	}
	return false
}

// CanTransition returns true if the transition from `from` to `to` is legally permitted.
func CanTransition(from, to ExecutionState) bool {
	targets, ok := validTransitions[from]
	if !ok {
		return false
	}
	return targets[to]
}

// IsTerminal returns true if the state cannot transition to any further state.
// Note: StateCommitted and StateEscalated are strictly terminal.
func IsTerminal(s ExecutionState) bool {
	return s == StateCommitted || s == StateEscalated
}

// StateTransition records a timestamped state transition event with optional diagnostic reason.
type StateTransition struct {
	From      ExecutionState `json:"from"`
	To        ExecutionState `json:"to"`
	Timestamp time.Time      `json:"timestamp"`
	Reason    string         `json:"reason,omitempty"`
}

// FSM is a thread-safe implementation of the 11-State monotonic remediation FSM.
type FSM struct {
	mu      sync.RWMutex
	current ExecutionState
	history []StateTransition
}

// NewFSM constructs a new FSM instance initialized at the given state (typically StateDetected).
func NewFSM(initial ExecutionState) (*FSM, error) {
	if !IsValidState(initial) {
		return nil, fmt.Errorf("invalid initial state: %q", initial)
	}
	return &FSM{
		current: initial,
		history: []StateTransition{
			{
				From:      "",
				To:        initial,
				Timestamp: time.Now().UTC(),
				Reason:    "initialization",
			},
		},
	}, nil
}

// Current returns the current state of the FSM.
func (m *FSM) Current() ExecutionState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Transition attempts to advance the FSM to the target state.
// Returns an error if the transition is invalid or non-monotonic.
func (m *FSM) Transition(to ExecutionState, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !IsValidState(to) {
		return fmt.Errorf("cannot transition to invalid state: %q", to)
	}

	if !CanTransition(m.current, to) {
		return fmt.Errorf("illegal monotonic transition: cannot move from %s to %s (reason: %s)", m.current, to, reason)
	}

	transition := StateTransition{
		From:      m.current,
		To:        to,
		Timestamp: time.Now().UTC(),
		Reason:    reason,
	}

	m.current = to
	m.history = append(m.history, transition)
	return nil
}

// History returns a copy of all recorded state transitions.
func (m *FSM) History() []StateTransition {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]StateTransition, len(m.history))
	copy(res, m.history)
	return res
}

// IsTerminal returns true if the current state is terminal.
func (m *FSM) IsTerminal() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return IsTerminal(m.current)
}
