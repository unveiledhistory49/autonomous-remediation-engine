package verifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"autonomous-remediation-engine/internal/model"
)

func TestCheckDiskFree(t *testing.T) {
	// Root or tmpfs check with 0% requirement must pass
	passed, pct, err := CheckDiskFree("/", 0.0)
	if err != nil {
		t.Fatalf("unexpected error for disk check on /: %v", err)
	}
	if !passed {
		t.Fatalf("expected 0%% minFree to pass, got free pct: %.2f%%", pct)
	}
	if pct < 0.0 || pct > 100.0 {
		t.Fatalf("pct %.2f out of bounds", pct)
	}

	// 100.0% minFree requirement on active system should fail
	passed, _, err = CheckDiskFree("/", 100.0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if passed {
		t.Fatalf("expected 100%% minFree to fail")
	}

	// Non-existent path
	_, _, err = CheckDiskFree("/nonexistent/directory/path/123", 10.0)
	if err == nil {
		t.Fatalf("expected error for non-existent path")
	}
}

func TestCheckProcessAlive(t *testing.T) {
	// Current process PID should be alive
	pid := os.Getpid()
	if !CheckProcessAlive(pid) {
		t.Fatalf("current process %d should be reported alive", pid)
	}

	// PID 0 or negative
	if CheckProcessAlive(0) {
		t.Fatalf("PID 0 should not be reported alive")
	}
	if CheckProcessAlive(-1) {
		t.Fatalf("PID -1 should not be reported alive")
	}

	// High PID that does not exist
	if CheckProcessAlive(4194300) {
		t.Fatalf("PID 4194300 should not be reported alive")
	}
}

func TestCheckHTTPHealth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	// 200 OK expected
	passed, err := CheckHTTPHealth(ts.URL+"/healthz", 1*time.Second, http.StatusOK)
	if err != nil || !passed {
		t.Fatalf("expected HTTP check to pass, got passed=%v, err=%v", passed, err)
	}

	// Status code mismatch (expected 200, got 500)
	passed, err = CheckHTTPHealth(ts.URL+"/broken", 1*time.Second, http.StatusOK)
	if passed || err == nil {
		t.Fatalf("expected failure for 500 error endpoint, got passed=%v", passed)
	}

	// Unreachable server
	passed, err = CheckHTTPHealth("http://127.0.0.1:54321/nonexistent", 100*time.Millisecond, http.StatusOK)
	if passed || err == nil {
		t.Fatalf("expected error for unreachable endpoint")
	}
}

func TestCheckFileExists(t *testing.T) {
	tempFile, err := os.CreateTemp("", "check-file-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	tempFile.Close()

	if !CheckFileExists(tempFile.Name()) {
		t.Fatalf("expected existing file to be reported as existing")
	}

	if CheckFileExists(filepath.Join(os.TempDir(), "nonexistent-file-998877.txt")) {
		t.Fatalf("expected non-existent file to return false")
	}
}

func TestVerifyPreAndPostconditions(t *testing.T) {
	ctx := context.Background()

	// 1. Disk Free Condition
	preDisk := model.Precondition{
		Name:       "disk-check",
		Type:       model.ConditionDiskFree,
		Target:     "/",
		MinFreePct: 0.0,
	}
	ok, err := VerifyPrecondition(ctx, preDisk)
	if err != nil || !ok {
		t.Fatalf("disk precondition failed: %v", err)
	}

	// 2. Process Alive Condition
	preProc := model.Precondition{
		Name: "proc-check",
		Type: model.ConditionProcessAlive,
		PID:  os.Getpid(),
	}
	ok, err = VerifyPrecondition(ctx, preProc)
	if err != nil || !ok {
		t.Fatalf("process precondition failed: %v", err)
	}

	// 3. File Exists Condition
	tempFile, _ := os.CreateTemp("", "pre-post-*")
	defer os.Remove(tempFile.Name())
	tempFile.Close()

	postFile := model.Postcondition{
		Name:   "file-check",
		Type:   model.ConditionFileExists,
		Target: tempFile.Name(),
	}
	ok, err = VerifyPostcondition(ctx, postFile)
	if err != nil || !ok {
		t.Fatalf("file postcondition failed: %v", err)
	}

	// 4. Custom Condition
	customPre := model.Precondition{
		Name: "custom",
		Type: model.ConditionCustom,
		CheckFn: func(ctx context.Context) (bool, error) {
			return true, nil
		},
	}
	ok, err = VerifyPrecondition(ctx, customPre)
	if err != nil || !ok {
		t.Fatalf("custom precondition failed: %v", err)
	}
}
