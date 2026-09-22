package executor

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"autonomous-remediation-engine/internal/model"
)

func TestExecutor_SuccessfulCommand(t *testing.T) {
	ex := NewExecutor()
	ctx := context.Background()

	act := model.Action{
		Name:    "echo-test",
		Binary:  "/bin/echo",
		Args:    []string{"remediation-engine-ok"},
		Timeout: 5 * time.Second,
	}

	clamp := model.BlastRadius{
		MaxExecutionTime: 10 * time.Second,
	}

	res, err := ex.Execute(ctx, act, clamp)
	if err != nil {
		t.Fatalf("expected command success, got: %v", err)
	}

	if !res.Success {
		t.Fatalf("expected res.Success == true")
	}

	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}

	if !strings.Contains(res.Stdout, "remediation-engine-ok") {
		t.Fatalf("unexpected stdout: %q", res.Stdout)
	}
}

func TestExecutor_TimeoutEnforcement(t *testing.T) {
	ex := NewExecutor()
	ctx := context.Background()

	act := model.Action{
		Name:    "sleep-test",
		Binary:  "/bin/sleep",
		Args:    []string{"2"},
		Timeout: 100 * time.Millisecond,
	}

	clamp := model.BlastRadius{
		MaxExecutionTime: 1 * time.Second,
	}

	res, err := ex.Execute(ctx, act, clamp)
	if err == nil {
		t.Fatalf("expected timeout error, but command succeeded")
	}

	if !errors.Is(err, ErrExecutionTimedOut) {
		t.Fatalf("expected ErrExecutionTimedOut, got: %v", err)
	}

	if res != nil && res.ExitCode != 124 {
		t.Fatalf("expected exit code 124 for timeout, got: %d", res.ExitCode)
	}
}

func TestExecutor_BlastRadius_MaxExecutionTimeClamp(t *testing.T) {
	ex := NewExecutor()
	ctx := context.Background()

	// Action wants 10s, but clamp limits to 100ms
	act := model.Action{
		Name:    "sleep-clamped",
		Binary:  "/bin/sleep",
		Args:    []string{"2"},
		Timeout: 10 * time.Second,
	}

	clamp := model.BlastRadius{
		MaxExecutionTime: 100 * time.Millisecond,
	}

	start := time.Now()
	_, err := ex.Execute(ctx, act, clamp)
	duration := time.Since(start)

	if err == nil {
		t.Fatalf("expected clamp timeout error, got nil")
	}

	if duration > 1*time.Second {
		t.Fatalf("clamp failed to enforce timeout quickly: elapsed %v", duration)
	}
}

func TestExecutor_BlastRadius_MaxBytesMutatedClamp(t *testing.T) {
	ex := NewExecutor()
	ctx := context.Background()

	act := model.Action{
		Name: "mutate-bytes",
		MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
			return &model.ExecutionResult{
				BytesMutated: 5000,
			}, nil
		},
	}

	clamp := model.BlastRadius{
		MaxBytesMutated: 1000, // Clamp is 1000 bytes
	}

	_, err := ex.Execute(ctx, act, clamp)
	if err == nil {
		t.Fatalf("expected ErrBlastRadiusExceeded, got nil")
	}

	if !errors.Is(err, ErrBlastRadiusExceeded) {
		t.Fatalf("expected ErrBlastRadiusExceeded, got %v", err)
	}
}

func TestExecutor_MutateFn_Success(t *testing.T) {
	ex := NewExecutor()
	ctx := context.Background()

	var mutated bool
	act := model.Action{
		Name: "mutate-ok",
		MutateFn: func(ctx context.Context) (*model.ExecutionResult, error) {
			mutated = true
			return &model.ExecutionResult{
				BytesMutated: 50,
				Stdout:       "all good",
			}, nil
		},
	}

	clamp := model.BlastRadius{
		MaxBytesMutated: 1000,
	}

	res, err := ex.Execute(ctx, act, clamp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mutated {
		t.Fatalf("expected mutation function to execute")
	}

	if !res.Success || res.BytesMutated != 50 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestExecutor_ProcessSignalDispatch(t *testing.T) {
	// Spawn a background process to test signal dispatch
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep process: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	pid := cmd.Process.Pid
	ex := NewExecutor()
	ctx := context.Background()

	act := model.Action{
		Name:      "signal-term",
		TargetPID: pid,
		Signal:    syscall.SIGTERM,
	}

	clamp := model.BlastRadius{
		MaxProcessesSignaled: 1,
	}

	res, err := ex.Execute(ctx, act, clamp)
	if err != nil {
		t.Fatalf("failed to signal process: %v", err)
	}

	if !res.Success {
		t.Fatalf("expected res.Success == true")
	}

	// Wait for process to exit
	_ = cmd.Wait()
}

func TestExecutor_InvalidAction(t *testing.T) {
	ex := NewExecutor()
	ctx := context.Background()

	act := model.Action{
		Name: "empty",
	}

	_, err := ex.Execute(ctx, act, model.BlastRadius{})
	if !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("expected ErrInvalidAction, got %v", err)
	}
}
