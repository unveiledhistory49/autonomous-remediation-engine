package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"autonomous-remediation-engine/internal/config"
	"autonomous-remediation-engine/internal/engine"
	"autonomous-remediation-engine/internal/ingress"
	"autonomous-remediation-engine/internal/runbooks"
)

// Daemon coordinates the full autonomous remediation runtime architecture.
type Daemon struct {
	cfg        *config.Config
	engine     *engine.Engine
	metrics    *ingress.Metrics
	unixServer *ingress.UnixSocketServer
	httpServer *ingress.HTTPServer
	poller     *ingress.Poller
	logger     *log.Logger
}

// NewDaemon initializes all engine subsystems and ingress servers from the provided config.
func NewDaemon(cfg *config.Config, logger *log.Logger) (*Daemon, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	if logger == nil {
		logger = log.New(os.Stdout, "[remediation-daemon] ", log.LstdFlags|log.LUTC)
	}

	engineCfg := engine.EngineConfig{
		LockDir:          cfg.LockDir,
		AuditLogPath:     cfg.AuditLogPath,
		JournalDir:       cfg.JournalDir,
		DampingStatePath: cfg.DampingStateFile,
		HostUUID:         cfg.HostUUID,
	}

	eng, err := engine.NewEngine(engineCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize engine: %w", err)
	}

	// Register the standard production runbooks from the catalog
	for _, rb := range runbooks.DefaultCatalog() {
		if err := eng.RegisterRunbook(rb); err != nil {
			return nil, fmt.Errorf("failed to register runbook %s: %w", rb.ID, err)
		}
	}

	metrics := ingress.NewMetrics()
	unixServer := ingress.NewUnixSocketServer(cfg.UnixSocketPath, eng, metrics)
	httpServer := ingress.NewHTTPServer(cfg.HTTPAddr, cfg.HMACSecret, eng, metrics)
	poller := ingress.NewPoller(cfg.PollInterval, cfg.MonitoredPaths, cfg.MonitoredServices, eng, metrics)

	return &Daemon{
		cfg:        cfg,
		engine:     eng,
		metrics:    metrics,
		unixServer: unixServer,
		httpServer: httpServer,
		poller:     poller,
		logger:     logger,
	}, nil
}

// Start launches the Unix socket, HTTP server, and background Poller concurrently.
func (d *Daemon) Start(ctx context.Context) error {
	d.logger.Printf("Starting Autonomous Remediation Daemon on host: %s", d.cfg.HostUUID)

	if err := d.unixServer.Start(); err != nil {
		return fmt.Errorf("unix socket startup failed: %w", err)
	}
	d.logger.Printf("Unix domain socket listening on: %s", d.cfg.UnixSocketPath)

	if err := d.httpServer.Start(); err != nil {
		_ = d.unixServer.Stop()
		return fmt.Errorf("HTTP webhook server startup failed: %w", err)
	}
	d.logger.Printf("HTTP server listening on: %s", d.httpServer.Addr())

	if err := d.poller.Start(ctx); err != nil {
		_ = d.httpServer.Stop(context.Background())
		_ = d.unixServer.Stop()
		return fmt.Errorf("background poller startup failed: %w", err)
	}
	d.logger.Printf("Autonomous background poller active (interval: %v)", d.cfg.PollInterval)

	return nil
}

// Stop gracefully stops all listeners, shuts down the poller, and flushes persistent journals.
func (d *Daemon) Stop() error {
	d.logger.Println("Initiating graceful daemon shutdown...")

	// 1. Stop background poller
	d.poller.Stop()
	d.logger.Println("Background poller stopped.")

	// 2. Shutdown HTTP server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.httpServer.Stop(shutdownCtx); err != nil {
		d.logger.Printf("HTTP server shutdown warning: %v", err)
	} else {
		d.logger.Println("HTTP webhook server stopped.")
	}

	// 3. Stop Unix socket server & unlink socket file
	if err := d.unixServer.Stop(); err != nil {
		d.logger.Printf("Unix socket shutdown warning: %v", err)
	} else {
		d.logger.Println("Unix socket listener stopped and socket unlinked.")
	}

	// 4. Close engine subsystems and flush audit journal
	if err := d.engine.Close(); err != nil {
		d.logger.Printf("Audit ledger flush warning: %v", err)
		return err
	}
	d.logger.Println("Audit ledger flushed and synchronized to disk.")
	d.logger.Println("Autonomous Remediation Daemon shutdown complete.")

	return nil
}

func main() {
	configPath := flag.String("config", "", "Path to daemon configuration file (JSON/YAML)")
	flag.Parse()

	logger := log.New(os.Stdout, "[remediation-daemon] ", log.LstdFlags|log.LUTC)

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	d, err := NewDaemon(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize daemon: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := d.Start(ctx); err != nil {
		logger.Fatalf("Daemon failed to start: %v", err)
	}

	// Intercept SIGINT / SIGTERM for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	sig := <-sigCh
	logger.Printf("Received termination signal %v, beginning shutdown...", sig)
	cancel()

	if err := d.Stop(); err != nil {
		logger.Fatalf("Daemon shutdown encountered error: %v", err)
	}
	os.Exit(0)
}
