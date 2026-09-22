package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

var (
	// ErrLockHeld is returned when a lock is currently held by another worker or process.
	ErrLockHeld = errors.New("lock already held")
	// ErrLockReleased is returned when an operation is performed on an already released lock.
	ErrLockReleased = errors.New("lock already released")
)

// Coordinator manages file-descriptor advisory locks for resources.
type Coordinator struct {
	lockDir string
	mu      sync.Mutex
}

// ResourceLock represents an acquired advisory lock on a resource.
type ResourceLock struct {
	ResourceID string
	Path       string
	file       *os.File
	released   bool
	mu         sync.Mutex
}

// NewCoordinator creates a lock coordinator backed by the specified directory.
// If lockDir is empty, a default path (/tmp/remediation-locks) is used.
func NewCoordinator(lockDir string) (*Coordinator, error) {
	if lockDir == "" {
		lockDir = "/tmp/remediation-locks"
	}
	if err := os.MkdirAll(lockDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create lock directory %s: %w", lockDir, err)
	}
	return &Coordinator{
		lockDir: lockDir,
	}, nil
}

// LockPathFor returns the deterministic filesystem path for the given resource lock.
func (c *Coordinator) LockPathFor(resourceID string) string {
	sanitized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, resourceID)
	sanitized = strings.Trim(sanitized, "_")
	if len(sanitized) > 64 {
		sanitized = sanitized[:64]
	}

	h := sha256.Sum256([]byte(resourceID))
	shortHash := hex.EncodeToString(h[:4]) // 8 hex characters

	var filename string
	if sanitized == "" {
		filename = fmt.Sprintf("res_%s.lock", shortHash)
	} else {
		filename = fmt.Sprintf("%s_%s.lock", sanitized, shortHash)
	}

	return filepath.Join(c.lockDir, filename)
}

// TryLock attempts to acquire an exclusive, non-blocking file advisory lock on resourceID.
// If the lock is already held, ErrLockHeld is returned.
func (c *Coordinator) TryLock(resourceID string) (*ResourceLock, error) {
	lockPath := c.LockPathFor(resourceID)
	return c.TryLockPath(resourceID, lockPath)
}

// TryLockPath attempts to acquire an exclusive, non-blocking lock on the explicit file path.
func (c *Coordinator) TryLockPath(resourceID, lockPath string) (*ResourceLock, error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to ensure lock directory: %w", err)
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}

	// Exclusive, non-blocking advisory lock
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLockHeld
		}
		return nil, fmt.Errorf("failed to acquire flock on %s: %w", lockPath, err)
	}

	return &ResourceLock{
		ResourceID: resourceID,
		Path:       lockPath,
		file:       f,
		released:   false,
	}, nil
}

// Unlock releases the advisory lock and closes the file descriptor.
// Safe for multiple calls (idempotent).
func (l *ResourceLock) Unlock() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.released || l.file == nil {
		return nil
	}

	l.released = true
	// Release advisory lock
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}

// IsReleased reports whether the lock has already been unlocked.
func (l *ResourceLock) IsReleased() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.released
}
