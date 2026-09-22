package damping

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// MaxExecutions10Min is the maximum allowed executions for a resource within 10 minutes.
	MaxExecutions10Min = 2
	// MaxExecutions1Hour is the maximum allowed executions for a resource within 1 hour.
	MaxExecutions1Hour = 4
	// DefaultCooldown is the minimum wait time between consecutive executions on a resource.
	DefaultCooldown = 300 * time.Second
	// DefaultQuarantineDuration is the duration for which automated actions are frozen upon breach.
	DefaultQuarantineDuration = 3600 * time.Second

	// Window10Min is the 10-minute evaluation window.
	Window10Min = 10 * time.Minute
	// Window1Hour is the 1-hour evaluation window.
	Window1Hour = 1 * time.Hour
)

// ResourceState maintains the flapping and execution history for a single resource.
type ResourceState struct {
	Resource        string      `json:"resource"`
	Executions      []time.Time `json:"executions"`
	Tripped         bool        `json:"tripped"`
	QuarantineUntil time.Time   `json:"quarantine_until,omitempty"`
	TripReason      string      `json:"trip_reason,omitempty"`
}

// Controller enforces the mathematical flapping damping model and sliding-window circuit breaker.
type Controller struct {
	mu        sync.RWMutex
	statePath string
	states    map[string]*ResourceState
	nowFn     func() time.Time
}

// NewController initializes a flapping damping controller.
// If statePath is non-empty, existing state is loaded from disk and mutations are persisted.
func NewController(statePath string) (*Controller, error) {
	c := &Controller{
		statePath: statePath,
		states:    make(map[string]*ResourceState),
		nowFn:     time.Now,
	}

	if statePath != "" {
		if err := c.load(); err != nil {
			return nil, fmt.Errorf("failed to load damping state: %w", err)
		}
	}

	return c, nil
}

// SetNowFunc overrides the current time provider, primarily for deterministic testing.
func (c *Controller) SetNowFunc(fn func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fn == nil {
		c.nowFn = time.Now
	} else {
		c.nowFn = fn
	}
}

func (c *Controller) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

// CanExecute evaluates the three mathematical damping rate equations from DESIGN.md Section 6.3:
// 1. Quarantined check: Is resource currently in quarantine?
// 2. Cooldown check: (t - t_last_execution(R)) >= 300 seconds
// 3. 10-minute rate limit: Count(A(R, 10 min)) <= 2
// 4. 1-hour rate limit: Count(A(R, 1 hour)) <= 4
//
// If any condition evaluates to false, the target circuit breaker trips to LOCKED (quarantine for 3600s).
func (c *Controller) CanExecute(resource string) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	st, ok := c.states[resource]
	if !ok {
		return true, ""
	}

	// 1. Check existing quarantine
	if st.Tripped {
		if now.Before(st.QuarantineUntil) {
			return false, fmt.Sprintf("FLAP_DAMPING_BREACH: resource %q quarantined until %s (reason: %s)",
				resource, st.QuarantineUntil.UTC().Format(time.RFC3339), st.TripReason)
		}
		// Quarantine expired; reset tripped state
		st.Tripped = false
		st.QuarantineUntil = time.Time{}
		st.TripReason = ""
		_ = c.saveLocked()
	}

	// 2. Cooldown constraint: (t - t_last_execution(R)) >= 300 seconds
	if len(st.Executions) > 0 {
		lastExec := st.Executions[len(st.Executions)-1]
		elapsed := now.Sub(lastExec)
		if elapsed < DefaultCooldown {
			reason := fmt.Sprintf("FLAP_DAMPING_BREACH: cooldown violation for %q: elapsed %v < %v",
				resource, elapsed.Round(time.Millisecond), DefaultCooldown)
			c.tripLocked(resource, DefaultQuarantineDuration, reason)
			_ = c.saveLocked()
			return false, reason
		}
	}

	// 3. 10-minute rate limit: Count(A(R, 10 min)) <= 2
	count10m := 0
	for _, t := range st.Executions {
		if now.Sub(t) <= Window10Min {
			count10m++
		}
	}
	if count10m >= MaxExecutions10Min {
		reason := fmt.Sprintf("FLAP_DAMPING_BREACH: 10-minute execution limit reached for %q: %d executions in last 10m (max %d)",
			resource, count10m, MaxExecutions10Min)
		c.tripLocked(resource, DefaultQuarantineDuration, reason)
		_ = c.saveLocked()
		return false, reason
	}

	// 4. 1-hour rate limit: Count(A(R, 1 hour)) <= 4
	count1h := 0
	for _, t := range st.Executions {
		if now.Sub(t) <= Window1Hour {
			count1h++
		}
	}
	if count1h >= MaxExecutions1Hour {
		reason := fmt.Sprintf("FLAP_DAMPING_BREACH: 1-hour execution limit reached for %q: %d executions in last 1h (max %d)",
			resource, count1h, MaxExecutions1Hour)
		c.tripLocked(resource, DefaultQuarantineDuration, reason)
		_ = c.saveLocked()
		return false, reason
	}

	return true, ""
}

// RecordExecution records a successful execution timestamp for the given resource.
func (c *Controller) RecordExecution(resource string) {
	c.RecordExecutionAt(resource, c.now())
}

// RecordExecutionAt records an execution at a specific timestamp.
func (c *Controller) RecordExecutionAt(resource string, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, ok := c.states[resource]
	if !ok {
		st = &ResourceState{
			Resource:   resource,
			Executions: make([]time.Time, 0, 8),
		}
		c.states[resource] = st
	}

	st.Executions = append(st.Executions, t)

	// Prune executions older than 24 hours to keep state file bounded
	cutoff := t.Add(-24 * time.Hour)
	pruned := make([]time.Time, 0, len(st.Executions))
	for _, execTime := range st.Executions {
		if execTime.After(cutoff) {
			pruned = append(pruned, execTime)
		}
	}
	st.Executions = pruned

	_ = c.saveLocked()
}

// Trip forces a resource into quarantine for quarantineDuration.
// If quarantineDuration <= 0, DefaultQuarantineDuration (3600s) is used.
func (c *Controller) Trip(resource string, quarantineDuration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if quarantineDuration <= 0 {
		quarantineDuration = DefaultQuarantineDuration
	}
	reason := fmt.Sprintf("manually tripped quarantine for %v", quarantineDuration)
	c.tripLocked(resource, quarantineDuration, reason)
	_ = c.saveLocked()
}

func (c *Controller) tripLocked(resource string, quarantineDuration time.Duration, reason string) {
	st, ok := c.states[resource]
	if !ok {
		st = &ResourceState{
			Resource: resource,
		}
		c.states[resource] = st
	}

	st.Tripped = true
	st.QuarantineUntil = c.now().Add(quarantineDuration)
	st.TripReason = reason
}

// Reset clears quarantine and execution history for the given resource.
func (c *Controller) Reset(resource string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.states, resource)
	_ = c.saveLocked()
}

// GetStatus returns a snapshot copy of the resource damping state.
func (c *Controller) GetStatus(resource string) *ResourceState {
	c.mu.RLock()
	defer c.mu.RUnlock()

	st, ok := c.states[resource]
	if !ok {
		return nil
	}

	cp := *st
	cp.Executions = make([]time.Time, len(st.Executions))
	copy(cp.Executions, st.Executions)
	return &cp
}

// GetAllStatuses returns snapshots of all tracked resource damping states.
func (c *Controller) GetAllStatuses() map[string]ResourceState {
	c.mu.RLock()
	defer c.mu.RUnlock()

	res := make(map[string]ResourceState, len(c.states))
	for k, st := range c.states {
		cp := *st
		cp.Executions = make([]time.Time, len(st.Executions))
		copy(cp.Executions, st.Executions)
		res[k] = cp
	}
	return res
}

func (c *Controller) load() error {
	data, err := os.ReadFile(c.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var loaded map[string]*ResourceState
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}
	if loaded != nil {
		c.states = loaded
	}
	return nil
}

func (c *Controller) saveLocked() error {
	if c.statePath == "" {
		return nil
	}

	dir := filepath.Dir(c.statePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c.states, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := c.statePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpFile, c.statePath)
}
