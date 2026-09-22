package runbooks

import (
	"errors"
	"fmt"
	"sync"

	"autonomous-remediation-engine/internal/model"
)

var (
	ErrRunbookNotFound = errors.New("runbook not found in catalog")
)

// DefaultDiskCleanupRunbook returns the standard production instance of RBK-DISK-001.
func DefaultDiskCleanupRunbook() *model.Runbook {
	return NewDiskCleanupRunbook(DefaultDiskCleanupConfig())
}

// DefaultServiceHangRecoveryRunbook returns the standard production instance of RBK-PROC-001.
func DefaultServiceHangRecoveryRunbook() *model.Runbook {
	return NewServiceHangRecoveryRunbook(DefaultServiceHangConfig())
}

// DefaultTLSCertRotationRunbook returns the standard production instance of RBK-TLS-001.
func DefaultTLSCertRotationRunbook() *model.Runbook {
	return NewTLSCertRotationRunbook(DefaultTLSRotationConfig())
}

// DefaultConfigRollbackRunbook returns the standard production instance of RBK-CFG-001.
func DefaultConfigRollbackRunbook() *model.Runbook {
	return NewConfigRollbackRunbook(DefaultConfigRollbackConfig())
}

// DefaultCatalog returns the 4 core production runbooks configured with production defaults.
func DefaultCatalog() []*model.Runbook {
	return []*model.Runbook{
		DefaultDiskCleanupRunbook(),
		DefaultServiceHangRecoveryRunbook(),
		DefaultTLSCertRotationRunbook(),
		DefaultConfigRollbackRunbook(),
	}
}

// Catalog represents a thread-safe registry of deterministic runbooks.
type Catalog struct {
	mu       sync.RWMutex
	runbooks map[string]*model.Runbook
}

// NewCatalog constructs an empty runbook catalog.
func NewCatalog() *Catalog {
	return &Catalog{
		runbooks: make(map[string]*model.Runbook),
	}
}

// NewDefaultCatalog constructs a catalog pre-populated with the 4 default production runbooks.
func NewDefaultCatalog() *Catalog {
	cat := NewCatalog()
	for _, rb := range DefaultCatalog() {
		_ = cat.Register(rb)
	}
	return cat
}

// Register registers a runbook in the catalog.
func (c *Catalog) Register(rb *model.Runbook) error {
	if rb == nil || rb.ID == "" {
		return errors.New("cannot register un-identified runbook")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.runbooks[rb.ID] = rb
	return nil
}

// Get retrieves a runbook by ID.
func (c *Catalog) Get(id string) (*model.Runbook, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rb, ok := c.runbooks[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrRunbookNotFound, id)
	}
	return rb, nil
}

// List returns all registered runbooks in the catalog.
func (c *Catalog) List() []*model.Runbook {
	c.mu.RLock()
	defer c.mu.RUnlock()

	list := make([]*model.Runbook, 0, len(c.runbooks))
	for _, rb := range c.runbooks {
		list = append(list, rb)
	}
	return list
}
