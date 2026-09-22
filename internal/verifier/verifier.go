package verifier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"
	"time"

	"autonomous-remediation-engine/internal/model"
)

// CheckDiskFree determines whether the available disk space at path is >= minFreePct.
// Uses syscall.Statfs for zero-dependency kernel ground-truth inspection.
func CheckDiskFree(path string, minFreePct float64) (bool, float64, error) {
	if path == "" {
		return false, 0, errors.New("empty path provided for disk check")
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return false, 0, fmt.Errorf("statfs failed on %s: %w", path, err)
	}

	if stat.Blocks == 0 {
		return false, 0, fmt.Errorf("filesystem at %s reports 0 total blocks", path)
	}

	// stat.Bavail represents free blocks available to unprivileged users
	freePct := (float64(stat.Bavail) / float64(stat.Blocks)) * 100.0
	passed := freePct >= minFreePct

	return passed, freePct, nil
}

// CheckProcessAlive determines whether a process with the given PID exists and is running.
// Uses syscall.Kill(pid, 0) to probe without side effects.
func CheckProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}

	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}

	// If EPERM, process exists and is active, but owned by another UID
	if errors.Is(err, syscall.EPERM) {
		return true
	}

	// ESRCH indicates no such process exists
	return false
}

// CheckHTTPHealth performs a loopback/HTTP probe asserting that the endpoint returns expectedStatus.
func CheckHTTPHealth(url string, timeout time.Duration, expectedStatus int) (bool, error) {
	if url == "" {
		return false, errors.New("empty URL for HTTP health check")
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if expectedStatus <= 0 {
		expectedStatus = http.StatusOK
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return false, fmt.Errorf("HTTP GET request failed for %s: %w", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != expectedStatus {
		return false, fmt.Errorf("HTTP check failed: expected status %d, got %d", expectedStatus, resp.StatusCode)
	}

	return true, nil
}

// CheckFileExists checks whether a file or directory exists at the given path.
func CheckFileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// VerifyPrecondition evaluates a single model.Precondition against OS ground truth.
func VerifyPrecondition(ctx context.Context, pre model.Precondition) (bool, error) {
	if pre.CheckFn != nil {
		return pre.CheckFn(ctx)
	}

	switch pre.Type {
	case model.ConditionDiskFree:
		passed, freePct, err := CheckDiskFree(pre.Target, pre.MinFreePct)
		if err != nil {
			return false, err
		}
		if !passed {
			return false, fmt.Errorf("disk free space on %s is %.2f%%, required >= %.2f%%", pre.Target, freePct, pre.MinFreePct)
		}
		return true, nil

	case model.ConditionProcessAlive:
		alive := CheckProcessAlive(pre.PID)
		if !alive {
			return false, fmt.Errorf("process with PID %d is not running", pre.PID)
		}
		return true, nil

	case model.ConditionHTTPHealth:
		return CheckHTTPHealth(pre.Target, pre.Timeout, pre.ExpectedStatus)

	case model.ConditionFileExists:
		exists := CheckFileExists(pre.Target)
		if !exists {
			return false, fmt.Errorf("target file does not exist: %s", pre.Target)
		}
		return true, nil

	case model.ConditionCustom:
		return false, errors.New("custom condition requires CheckFn")

	default:
		return false, fmt.Errorf("unsupported precondition type: %s", pre.Type)
	}
}

// VerifyPostcondition evaluates a single model.Postcondition against OS ground truth.
func VerifyPostcondition(ctx context.Context, post model.Postcondition) (bool, error) {
	if post.CheckFn != nil {
		return post.CheckFn(ctx)
	}

	switch post.Type {
	case model.ConditionDiskFree:
		passed, freePct, err := CheckDiskFree(post.Target, post.MinFreePct)
		if err != nil {
			return false, err
		}
		if !passed {
			return false, fmt.Errorf("postcondition disk free space on %s is %.2f%%, required >= %.2f%%", post.Target, freePct, post.MinFreePct)
		}
		return true, nil

	case model.ConditionProcessAlive:
		alive := CheckProcessAlive(post.PID)
		if !alive {
			return false, fmt.Errorf("postcondition process with PID %d is not running", post.PID)
		}
		return true, nil

	case model.ConditionHTTPHealth:
		return CheckHTTPHealth(post.Target, post.Timeout, post.ExpectedStatus)

	case model.ConditionFileExists:
		exists := CheckFileExists(post.Target)
		if !exists {
			return false, fmt.Errorf("postcondition target file does not exist: %s", post.Target)
		}
		return true, nil

	case model.ConditionCustom:
		return false, errors.New("custom postcondition requires CheckFn")

	default:
		return false, fmt.Errorf("unsupported postcondition type: %s", post.Type)
	}
}
