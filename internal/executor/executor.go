package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"

	"autonomous-remediation-engine/internal/model"
)

var (
	// ErrBlastRadiusExceeded is returned when execution violates defined bounds.
	ErrBlastRadiusExceeded = errors.New("blast radius clamp exceeded")
	// ErrExecutionTimedOut is returned when execution exceeds its deadline.
	ErrExecutionTimedOut = errors.New("action execution timed out")
	// ErrInvalidAction indicates that the action cannot be executed.
	ErrInvalidAction = errors.New("invalid action configuration")
)

// Executor coordinates sandboxed action execution with strict deadlines and clamps.
type Executor struct {
	DefaultTimeout time.Duration
}

// NewExecutor initializes an action runner.
func NewExecutor() *Executor {
	return &Executor{
		DefaultTimeout: 15 * time.Second,
	}
}

// Execute executes a remediation action inside a sandboxed boundary.
func (e *Executor) Execute(ctx context.Context, action model.Action, clamp model.BlastRadius) (*model.ExecutionResult, error) {
	// 1. Calculate effective timeout clamped by blast-radius limits
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = e.DefaultTimeout
	}
	if clamp.MaxExecutionTime > 0 && timeout > clamp.MaxExecutionTime {
		timeout = clamp.MaxExecutionTime
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 2. Handle programmatic mutation functions (useful for in-process actions and unit tests)
	if action.MutateFn != nil {
		start := time.Now()
		res, err := action.MutateFn(execCtx)
		duration := time.Since(start)

		if res == nil {
			res = &model.ExecutionResult{}
		}
		res.Duration = duration

		if execCtx.Err() == context.DeadlineExceeded {
			res.ExitCode = 124
			res.Error = "execution deadline exceeded"
			return res, ErrExecutionTimedOut
		}

		if clamp.MaxBytesMutated > 0 && res.BytesMutated > clamp.MaxBytesMutated {
			return res, fmt.Errorf("%w: mutated %d bytes, max allowed is %d",
				ErrBlastRadiusExceeded, res.BytesMutated, clamp.MaxBytesMutated)
		}

		if err != nil {
			res.Success = false
			res.Error = err.Error()
			return res, err
		}

		res.Success = true
		return res, nil
	}

	// 3. Handle process signaling
	if action.TargetPID > 0 && action.Signal != 0 {
		if clamp.MaxProcessesSignaled > 0 && clamp.MaxProcessesSignaled < 1 {
			return nil, fmt.Errorf("%w: process signaling prohibited by clamp", ErrBlastRadiusExceeded)
		}

		start := time.Now()
		// Probe process liveness before signaling
		if err := syscall.Kill(action.TargetPID, 0); err != nil {
			return &model.ExecutionResult{
				ExitCode: 1,
				Duration: time.Since(start),
				Error:    fmt.Sprintf("target PID %d is not running: %v", action.TargetPID, err),
			}, fmt.Errorf("target PID %d is not alive: %w", action.TargetPID, err)
		}

		// Dispatch signal
		err := syscall.Kill(action.TargetPID, action.Signal)
		duration := time.Since(start)
		if err != nil {
			return &model.ExecutionResult{
				ExitCode: 1,
				Duration: duration,
				Error:    err.Error(),
			}, fmt.Errorf("failed to send signal %v to PID %d: %w", action.Signal, action.TargetPID, err)
		}

		return &model.ExecutionResult{
			ExitCode: 0,
			Duration: duration,
			Success:  true,
		}, nil
	}

	// 4. Handle direct command execution
	if action.Binary != "" {
		start := time.Now()
		cmd := exec.CommandContext(execCtx, action.Binary, action.Args...)

		// Isolate into independent process group
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
		}

		// Apply credential demotion only if caller is running as root
		if syscall.Getuid() == 0 && (action.UID > 0 || action.GID > 0) {
			cmd.SysProcAttr.Credential = &syscall.Credential{
				Uid: action.UID,
				Gid: action.GID,
			}
		}

		var stdoutBuf, stderrBuf bytes.Buffer
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf

		err := cmd.Run()
		duration := time.Since(start)

		res := &model.ExecutionResult{
			Duration: duration,
			Stdout:   stdoutBuf.String(),
			Stderr:   stderrBuf.String(),
		}

		if err != nil {
			if execCtx.Err() == context.DeadlineExceeded {
				if cmd.Process != nil {
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				}
				res.ExitCode = 124
				res.Error = "execution timed out"
				return res, ErrExecutionTimedOut
			}

			if exitErr, ok := err.(*exec.ExitError); ok {
				res.ExitCode = exitErr.ExitCode()
				res.Error = stderrBuf.String()
				return res, fmt.Errorf("action %s exited with code %d: %s", action.Name, res.ExitCode, res.Error)
			}

			res.ExitCode = 1
			res.Error = err.Error()
			return res, fmt.Errorf("action %s failed to spawn: %w", action.Name, err)
		}

		res.ExitCode = 0
		res.Success = true
		return res, nil
	}

	return nil, ErrInvalidAction
}
