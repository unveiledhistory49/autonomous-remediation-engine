package ingress

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"autonomous-remediation-engine/internal/audit"
	"autonomous-remediation-engine/internal/damping"
	"autonomous-remediation-engine/internal/model"
)

// EngineProvider represents the required engine interface for HTTP endpoints.
type EngineProvider interface {
	AlertProcessor
	IsHealthy() (bool, string)
	ListRunbooks() []*model.Runbook
	Damping() *damping.Controller
	Ledger() *audit.Ledger
}

// HTTPServer provides the hardened HTTP webhook, health check, status, and Prometheus metrics endpoints.
type HTTPServer struct {
	addr       string
	hmacSecret string
	engine     EngineProvider
	metrics    *Metrics
	server     *http.Server
	listener   net.Listener
	startTime  time.Time
	mu         sync.Mutex
	running    bool
}

// NewHTTPServer constructs a new HTTPServer instance.
func NewHTTPServer(addr string, hmacSecret string, engine EngineProvider, metrics *Metrics) *HTTPServer {
	return &HTTPServer{
		addr:       addr,
		hmacSecret: hmacSecret,
		engine:     engine,
		metrics:    metrics,
		startTime:  time.Now(),
	}
}

// Addr returns the configured or bound network address.
func (s *HTTPServer) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}

// Start binds to the configured network address and launches the HTTP listener loop.
func (s *HTTPServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("http server is already running")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/alerts", s.handleAlerts)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/metrics", s.handleMetrics)

	server := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on HTTP addr %s: %w", s.addr, err)
	}

	s.listener = l
	s.server = server
	s.running = true
	s.mu.Unlock()

	go func() {
		_ = server.Serve(l)
	}()

	return nil
}

// Stop gracefully stops the HTTP server.
func (s *HTTPServer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.server == nil {
		return nil
	}
	s.running = false
	return s.server.Shutdown(ctx)
}

// POST /v1/alerts: Validates HMAC-SHA256 signature in X-Signature-256 header (if secret configured)
// via crypto/subtle.ConstantTimeCompare, processes alert, returns execution result with status 200 (or 400/401/422).
func (s *HTTPServer) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Clamp request body to 1 MB per DESIGN.md
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "failed to read request body or exceeded 1MB limit"})
		return
	}

	// Validate HMAC-SHA256 signature if secret is configured
	if s.hmacSecret != "" {
		sigHeader := r.Header.Get("X-Signature-256")
		if sigHeader == "" {
			sigHeader = r.Header.Get("X-Remediation-Signature")
		}
		sigHeader = strings.TrimPrefix(sigHeader, "sha256=")

		if sigHeader == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing signature in X-Signature-256 header"})
			return
		}

		mac := hmac.New(sha256.New, []byte(s.hmacSecret))
		mac.Write(body)
		expectedHex := hex.EncodeToString(mac.Sum(nil))

		if subtle.ConstantTimeCompare([]byte(strings.ToLower(sigHeader)), []byte(strings.ToLower(expectedHex))) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid HMAC signature"})
			return
		}
	}

	// Parse JSON alert payload
	var alert model.Alert
	if err := json.Unmarshal(body, &alert); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("malformed alert JSON: %v", err)})
		return
	}

	// Validate required fields
	if alert.ID == "" || alert.ResourceID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "alert 'id' and 'resource_id' are required"})
		return
	}

	if alert.ReceivedAt.IsZero() {
		alert.ReceivedAt = time.Now().UTC()
	}
	if alert.Source == "" {
		alert.Source = "http_webhook"
	}

	res, _ := s.engine.ProcessAlert(&alert)
	if s.metrics != nil && res != nil {
		s.metrics.RecordRemediationResult(res)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(res)
}

// GET /healthz: Returns 200 OK if daemon is healthy (lock dir writable, audit ledger active).
func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	healthy, reason := s.engine.IsHealthy()
	w.Header().Set("Content-Type", "application/json")

	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "unhealthy",
			"reason": reason,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         "ok",
		"uptime_seconds": time.Since(s.startTime).Seconds(),
	})
}

// GET /v1/status: Returns JSON with active runbooks, damping status, and latest audit ledger hash.
func (s *HTTPServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var runbooksSummary []map[string]any
	for _, rb := range s.engine.ListRunbooks() {
		runbooksSummary = append(runbooksSummary, map[string]any{
			"id":                 rb.ID,
			"name":               rb.Name,
			"target_resource_id": rb.TargetResourceID,
			"severity":           rb.Severity,
		})
	}

	var dampingStatus any = map[string]any{}
	if s.engine.Damping() != nil {
		dampingStatus = s.engine.Damping().GetAllStatuses()
	}

	tailHash := ""
	if s.engine.Ledger() != nil {
		tailHash = s.engine.Ledger().LastHash()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":            "running",
		"uptime_seconds":    time.Since(s.startTime).Seconds(),
		"active_runbooks":   runbooksSummary,
		"damping_status":    dampingStatus,
		"latest_audit_hash": tailHash,
	})
}

// GET /metrics: Exposes Prometheus-compatible text metrics for SLOs.
func (s *HTTPServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	if s.metrics != nil {
		_, _ = w.Write([]byte(s.metrics.RenderPrometheus()))
	}
}
