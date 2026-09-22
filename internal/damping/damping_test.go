package damping

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDamping_CooldownConstraint(t *testing.T) {
	c, err := NewController("")
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}

	baseTime := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	currentTime := baseTime
	c.SetNowFunc(func() time.Time { return currentTime })

	res := "test-resource-cooldown"

	// 1. Initial check must succeed
	canExec, reason := c.CanExecute(res)
	if !canExec {
		t.Fatalf("expected initial CanExecute to return true, got false (%s)", reason)
	}

	// 2. Record first execution
	c.RecordExecution(res)

	// 3. Check 100 seconds later (elapsed 100s < 300s cooldown)
	currentTime = baseTime.Add(100 * time.Second)
	canExec, reason = c.CanExecute(res)
	if canExec {
		t.Fatalf("expected CanExecute to fail due to cooldown violation, got true")
	}
	if !strings.Contains(reason, "cooldown violation") {
		t.Fatalf("expected cooldown violation in reason, got %q", reason)
	}

	// 4. Circuit breaker should now be tripped to quarantine (3600s)
	status := c.GetStatus(res)
	if status == nil || !status.Tripped {
		t.Fatalf("expected resource to be tripped after cooldown violation")
	}

	// 5. Even at 301 seconds, it should still be blocked because it tripped quarantine
	currentTime = baseTime.Add(301 * time.Second)
	canExec, reason = c.CanExecute(res)
	if canExec {
		t.Fatalf("expected CanExecute to remain blocked due to quarantine, got true")
	}
	if !strings.Contains(reason, "quarantined") {
		t.Fatalf("expected quarantine reason, got %q", reason)
	}

	// 6. Reset should clear tripped quarantine
	c.Reset(res)
	canExec, reason = c.CanExecute(res)
	if !canExec {
		t.Fatalf("expected CanExecute to succeed after Reset, got false (%s)", reason)
	}

	// 7. Verify legitimate cooldown: record at T=0, advance by 301s, must succeed
	c.RecordExecution(res)
	currentTime = currentTime.Add(301 * time.Second)
	canExec, reason = c.CanExecute(res)
	if !canExec {
		t.Fatalf("expected CanExecute to succeed after 301s cooldown, got false (%s)", reason)
	}
}

func TestDamping_10MinuteLimit(t *testing.T) {
	c, err := NewController("")
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}

	baseTime := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	currentTime := baseTime
	c.SetNowFunc(func() time.Time { return currentTime })

	res := "test-resource-10min"

	// Execution 1 at T=0
	c.RecordExecution(res)

	// Advance time past cooldown: T = 305s (> 300s cooldown, within 10 min)
	currentTime = baseTime.Add(305 * time.Second)

	// CanExecute for 2nd execution should be allowed (count in 10m is 1 < 2)
	canExec, reason := c.CanExecute(res)
	if !canExec {
		t.Fatalf("expected 2nd execution to be allowed, got false (%s)", reason)
	}
	c.RecordExecution(res)

	// Advance time past cooldown again: T = 610s (> 300s cooldown from 2nd exec)
	// But count in last 10m is now 2 (at T=0 and T=305s, within 610 - 600 = 10s... wait, T=0 is at 610s ago)
	// Let's set T = 550s (cooldown from 305s is 245s < 300s, so let's adjust timestamps carefully)
	// Execution 1: T = 0
	// Execution 2: T = 301s (valid cooldown, count=2)
	// At T = 500s: cooldown from 301s is 199s (cooldown breach)
	// At T = 602s: cooldown from 301s is 301s (>300s). But T=602s is within 10 minutes (600s) of T=301s!
	// Wait, at T=602s, count in [2s, 602s] has only T=301s (1 execution).
	// To have 2 executions within the 10-minute window:
	// T1 = 0s
	// T2 = 301s
	// Now at T3 = 590s (590s - 0s = 590s <= 600s, so both T1 and T2 are within 10m!)
	// Wait, cooldown from T2 (301s) at 590s is 289s < 300s.
	// Can we have T1 = 0s, T2 = 301s, and T3 = 601s?
	// At 601s, T1 (0s) is 601s ago (> 600s).
	// But what if T1 was at 0s, and T2 was at 300s?
	// Then at T = 600s:
	// T1 (0s) is at exactly 600s ago (within 10m window: 600s <= 10m).
	// T2 (300s) is at 300s ago (elapsed cooldown: 300s >= 300s).
	// Both executions (0s and 300s) are in the last 10m window [0, 600s]!
	// So count10m == 2!
	// Cooldown is 300s (>= 300s).
	// Thus, cooldown passes, but 10-minute limit (count >= 2) fails!

	c.Reset(res)
	currentTime = baseTime

	// Exec 1 at T = 0
	c.RecordExecution(res)

	// Exec 2 at T = 300s
	currentTime = baseTime.Add(300 * time.Second)
	c.RecordExecution(res)

	// Attempt Exec 3 at T = 600s (elapsed since exec 2 is 300s, but both exec 1 and exec 2 are <= 600s ago)
	currentTime = baseTime.Add(600 * time.Second)
	canExec, reason = c.CanExecute(res)
	if canExec {
		t.Fatalf("expected 3rd execution to be blocked by 10-minute rate limit, got true")
	}
	if !strings.Contains(reason, "10-minute execution limit") {
		t.Fatalf("expected 10-minute limit reason, got %q", reason)
	}

	// Verify breaker tripped
	status := c.GetStatus(res)
	if status == nil || !status.Tripped {
		t.Fatalf("expected breaker to be tripped")
	}
}

func TestDamping_1HourLimit(t *testing.T) {
	c, err := NewController("")
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}

	baseTime := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	currentTime := baseTime
	c.SetNowFunc(func() time.Time { return currentTime })

	res := "test-resource-1hour"

	// 4 executions spaced across the hour, each obeying cooldown (>300s) and 10-minute limit (<= 2 per 10m):
	// Exec 1: T = 0m
	// Exec 2: T = 6m (cooldown 6m > 5m, in [0, 6m] count=2)
	// Exec 3: T = 18m (cooldown 12m > 5m, in [8m, 18m] count=1 <= 2)
	// Exec 4: T = 25m (cooldown 7m > 5m, in [15m, 25m] count=2 <= 2)
	// Total executions in 1 hour = 4.
	//
	// At T = 38m (cooldown 13m > 5m, in [28m, 38m] count=0 <= 2):
	// Total executions in last 1 hour (since T=0) = 4!
	// 5th execution should fail with 1-hour rate limit!

	timeline := []time.Duration{
		0,
		6 * time.Minute,
		18 * time.Minute,
		25 * time.Minute,
	}

	for i, offset := range timeline {
		currentTime = baseTime.Add(offset)
		canExec, reason := c.CanExecute(res)
		if !canExec {
			t.Fatalf("execution %d at offset %v unexpectedly rejected: %s", i+1, offset, reason)
		}
		c.RecordExecution(res)
	}

	// Now at T = 38 minutes (within 1 hour from baseTime)
	currentTime = baseTime.Add(38 * time.Minute)
	canExec, reason := c.CanExecute(res)
	if canExec {
		t.Fatalf("expected 5th execution within 1 hour to be blocked, got true")
	}
	if !strings.Contains(reason, "1-hour execution limit") {
		t.Fatalf("expected 1-hour limit reason, got %q", reason)
	}

	// Breaker should be tripped
	status := c.GetStatus(res)
	if status == nil || !status.Tripped {
		t.Fatalf("expected breaker to be tripped")
	}
}

func TestDamping_QuarantineTripAndExpiry(t *testing.T) {
	c, err := NewController("")
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}

	baseTime := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	currentTime := baseTime
	c.SetNowFunc(func() time.Time { return currentTime })

	res := "test-quarantine"

	// Manually trip quarantine for 1800s (30m)
	c.Trip(res, 1800*time.Second)

	status := c.GetStatus(res)
	if status == nil || !status.Tripped {
		t.Fatalf("expected resource to be tripped")
	}

	// Check at T = 10m (quarantine still active)
	currentTime = baseTime.Add(10 * time.Minute)
	canExec, reason := c.CanExecute(res)
	if canExec {
		t.Fatalf("expected CanExecute to be blocked during quarantine")
	}
	if !strings.Contains(reason, "quarantined") {
		t.Fatalf("expected quarantined reason, got %q", reason)
	}

	// Advance past quarantine expiration: T = 31m (> 30m)
	currentTime = baseTime.Add(31 * time.Minute)
	canExec, reason = c.CanExecute(res)
	if !canExec {
		t.Fatalf("expected CanExecute to succeed after quarantine expired, got false (%s)", reason)
	}

	status = c.GetStatus(res)
	if status != nil && status.Tripped {
		t.Fatalf("expected tripped to be cleared after expiry")
	}
}

func TestDamping_StateSaveAndReload(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "damping-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	stateFile := filepath.Join(tempDir, "damping_state.json")

	c1, err := NewController(stateFile)
	if err != nil {
		t.Fatalf("failed to create c1: %v", err)
	}

	baseTime := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	c1.SetNowFunc(func() time.Time { return baseTime })

	resA := "resource-alpha"
	resB := "resource-beta"

	c1.RecordExecution(resA)
	c1.Trip(resB, 3600*time.Second)

	// Ensure file exists on disk
	if _, err := os.Stat(stateFile); err != nil {
		t.Fatalf("state file was not written: %v", err)
	}

	// Now instantiate a new controller from the same file
	c2, err := NewController(stateFile)
	if err != nil {
		t.Fatalf("failed to create c2: %v", err)
	}
	c2.SetNowFunc(func() time.Time { return baseTime })

	// Check resA state in c2
	stA := c2.GetStatus(resA)
	if stA == nil {
		t.Fatalf("expected resA to exist in reloaded state")
	}
	if len(stA.Executions) != 1 {
		t.Fatalf("expected 1 execution for resA, got %d", len(stA.Executions))
	}

	// Check resB state in c2
	stB := c2.GetStatus(resB)
	if stB == nil || !stB.Tripped {
		t.Fatalf("expected resB to be tripped in reloaded state")
	}

	// Cooldown check on resA via c2 at baseTime + 10s must fail
	c2.SetNowFunc(func() time.Time { return baseTime.Add(10 * time.Second) })
	canExec, reason := c2.CanExecute(resA)
	if canExec {
		t.Fatalf("expected cooldown violation in reloaded controller, got true")
	}
	if !strings.Contains(reason, "cooldown violation") {
		t.Fatalf("expected cooldown violation, got %s", reason)
	}

	// Reset resA and resB via c2
	c2.Reset(resA)
	c2.Reset(resB)

	// Recreate c3 to ensure resets were persisted
	c3, err := NewController(stateFile)
	if err != nil {
		t.Fatalf("failed to create c3: %v", err)
	}
	if c3.GetStatus(resA) != nil {
		t.Fatalf("expected resA to be deleted after reset")
	}
	if c3.GetStatus(resB) != nil {
		t.Fatalf("expected resB to be deleted after reset")
	}
}

func TestDamping_ThreadSafety(t *testing.T) {
	c, err := NewController("")
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}

	var wg sync.WaitGroup
	workers := 16
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			res := fmt.Sprintf("concurrent-res-%d", workerID%4)
			for j := 0; j < iterations; j++ {
				switch j % 4 {
				case 0:
					_, _ = c.CanExecute(res)
				case 1:
					c.RecordExecution(res)
				case 2:
					_ = c.GetStatus(res)
				case 3:
					if j%20 == 0 {
						c.Reset(res)
					}
				}
			}
		}(i)
	}

	wg.Wait()
}
