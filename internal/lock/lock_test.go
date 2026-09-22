package lock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCoordinator_AcquireAndRelease(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lock-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	coord, err := NewCoordinator(tempDir)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	res := "service/ai-gateway"
	lock1, err := coord.TryLock(res)
	if err != nil {
		t.Fatalf("expected successful lock acquisition, got: %v", err)
	}
	if lock1 == nil || lock1.file == nil {
		t.Fatalf("expected non-nil lock")
	}

	if lock1.IsReleased() {
		t.Fatalf("lock should not be marked released")
	}

	// Release lock
	if err := lock1.Unlock(); err != nil {
		t.Fatalf("failed to unlock: %v", err)
	}

	if !lock1.IsReleased() {
		t.Fatalf("lock should be marked released")
	}

	// Idempotent unlock
	if err := lock1.Unlock(); err != nil {
		t.Fatalf("second unlock should not error: %v", err)
	}
}

func TestCoordinator_MutualExclusionCollision(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lock-test-collision-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	coord, err := NewCoordinator(tempDir)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	res := "/var/log"
	lock1, err := coord.TryLock(res)
	if err != nil {
		t.Fatalf("first lock failed: %v", err)
	}
	defer lock1.Unlock()

	// Second attempt should fail with ErrLockHeld
	lock2, err := coord.TryLock(res)
	if !errors.Is(err, ErrLockHeld) {
		if lock2 != nil {
			lock2.Unlock()
		}
		t.Fatalf("expected ErrLockHeld, got err=%v", err)
	}

	// Release lock 1
	if err := lock1.Unlock(); err != nil {
		t.Fatalf("unlock lock1 failed: %v", err)
	}

	// Now third attempt should succeed
	lock3, err := coord.TryLock(res)
	if err != nil {
		t.Fatalf("expected successful lock after release, got: %v", err)
	}
	defer lock3.Unlock()
}

func TestCoordinator_IndependentResources(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lock-test-multi-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	coord, err := NewCoordinator(tempDir)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	res1 := "ai-gateway"
	res2 := "guardrail-proxy"

	lock1, err := coord.TryLock(res1)
	if err != nil {
		t.Fatalf("failed to lock res1: %v", err)
	}
	defer lock1.Unlock()

	lock2, err := coord.TryLock(res2)
	if err != nil {
		t.Fatalf("failed to lock res2: %v", err)
	}
	defer lock2.Unlock()

	if lock1.Path == lock2.Path {
		t.Fatalf("expected different paths for different resources: %s == %s", lock1.Path, lock2.Path)
	}
}

func TestCoordinator_DirectPathLock(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lock-test-path-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	coord, err := NewCoordinator(tempDir)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	directPath := filepath.Join(tempDir, "custom.lock")
	lock1, err := coord.TryLockPath("custom", directPath)
	if err != nil {
		t.Fatalf("failed to lock direct path: %v", err)
	}
	defer lock1.Unlock()

	_, err = coord.TryLockPath("custom", directPath)
	if !errors.Is(err, ErrLockHeld) {
		t.Fatalf("expected ErrLockHeld for direct path, got %v", err)
	}
}
