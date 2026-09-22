package ingress

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"autonomous-remediation-engine/internal/config"
	"autonomous-remediation-engine/internal/model"
	"autonomous-remediation-engine/internal/verifier"
)

// Poller runs autonomous background health monitoring across disk paths and services.
type Poller struct {
	interval  time.Duration
	paths     []config.PathConfig
	services  []config.ServiceConfig
	processor AlertProcessor
	metrics   *Metrics
	quit      chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	running   bool
}

// NewPoller constructs a new autonomous monitoring Poller.
func NewPoller(
	interval time.Duration,
	paths []config.PathConfig,
	services []config.ServiceConfig,
	processor AlertProcessor,
	metrics *Metrics,
) *Poller {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &Poller{
		interval:  interval,
		paths:     paths,
		services:  services,
		processor: processor,
		metrics:   metrics,
		quit:      make(chan struct{}),
	}
}

// Start launches the background polling ticker loop.
func (p *Poller) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = true
	p.mu.Unlock()

	p.wg.Add(1)
	go p.loop(ctx)
	return nil
}

func (p *Poller) loop(ctx context.Context) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Initial check on boot
	p.PollOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.quit:
			return
		case <-ticker.C:
			p.PollOnce(ctx)
		}
	}
}

// PollOnce executes an immediate health check across all configured paths and services.
func (p *Poller) PollOnce(ctx context.Context) {
	p.pollDiskPaths(ctx)
	p.pollServices(ctx)
}

func (p *Poller) pollDiskPaths(ctx context.Context) {
	for _, pc := range p.paths {
		if pc.Path == "" {
			continue
		}

		passed, freePct, err := verifier.CheckDiskFree(pc.Path, pc.MinFreePct)
		if err != nil || !passed {
			// Breach detected: construct and dispatch autonomous alert
			alert := &model.Alert{
				ID:          fmt.Sprintf("poller-disk-%s-%d", sanitizeTag(pc.Path), time.Now().UnixNano()),
				Fingerprint: fmt.Sprintf("disk-pressure-%s", pc.Path),
				Source:      "autonomous-poller",
				ResourceID:  pc.Path,
				Severity:    model.SeverityHigh,
				Labels: map[string]string{
					"alertname":  "DiskVolumeSaturation",
					"runbook_id": "RBK-DISK-001",
					"resource":   pc.Path,
				},
				Annotations: map[string]string{
					"min_free_pct":     fmt.Sprintf("%.2f", pc.MinFreePct),
					"current_free_pct": fmt.Sprintf("%.2f", freePct),
					"error":            fmt.Sprintf("%v", err),
				},
				ReceivedAt: time.Now().UTC(),
			}

			res, _ := p.processor.ProcessAlert(alert)
			if p.metrics != nil && res != nil {
				p.metrics.RecordRemediationResult(res)
			}
		}
	}
}

func (p *Poller) pollServices(ctx context.Context) {
	for _, sc := range p.services {
		if sc.Name == "" {
			continue
		}

		unhealthy := false
		var failureReason string

		// 1. Probe via HTTP /healthz if HealthURL is provided
		if sc.HealthURL != "" {
			ok, hErr := verifier.CheckHTTPHealth(sc.HealthURL, 1500*time.Millisecond, 200)
			if !ok || hErr != nil {
				unhealthy = true
				failureReason = fmt.Sprintf("health check failed for %s: %v", sc.HealthURL, hErr)
			}
		} else if sc.PIDFile != "" {
			// 2. Check process alive via PID file
			pidData, rErr := os.ReadFile(sc.PIDFile)
			if rErr != nil {
				unhealthy = true
				failureReason = fmt.Sprintf("failed to read PID file %s: %v", sc.PIDFile, rErr)
			} else {
				pid, pErr := strconv.Atoi(strings.TrimSpace(string(pidData)))
				if pErr != nil || !verifier.CheckProcessAlive(pid) {
					unhealthy = true
					failureReason = fmt.Sprintf("process with PID %d not alive", pid)
				}
			}
		}

		if unhealthy {
			// Service unhealthy: construct and dispatch autonomous alert
			alert := &model.Alert{
				ID:          fmt.Sprintf("poller-svc-%s-%d", sanitizeTag(sc.Name), time.Now().UnixNano()),
				Fingerprint: fmt.Sprintf("service-unhealthy-%s", sc.Name),
				Source:      "autonomous-poller",
				ResourceID:  sc.Name,
				Severity:    model.SeverityCritical,
				Labels: map[string]string{
					"alertname":  "ServiceUnhealthyDeadlock",
					"runbook_id": "RBK-PROC-001",
					"service":    sc.Name,
				},
				Annotations: map[string]string{
					"health_url": sc.HealthURL,
					"pid_file":   sc.PIDFile,
					"reason":     failureReason,
				},
				ReceivedAt: time.Now().UTC(),
			}

			res, _ := p.processor.ProcessAlert(alert)
			if p.metrics != nil && res != nil {
				p.metrics.RecordRemediationResult(res)
			}
		}
	}
}

// Stop terminates the poller and waits for the worker loop to exit.
func (p *Poller) Stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	close(p.quit)
	p.mu.Unlock()

	p.wg.Wait()
}

func sanitizeTag(s string) string {
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "root"
	}
	return s
}
