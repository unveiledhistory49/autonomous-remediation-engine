package ingress

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"autonomous-remediation-engine/internal/engine"
	"autonomous-remediation-engine/internal/model"
)

// AlertProcessor defines the engine execution interface for ingesting alerts.
type AlertProcessor interface {
	ProcessAlert(alert *model.Alert) (*engine.RemediationResult, error)
}

// UnixSocketServer hosts an unprivileged or privileged Unix domain socket endpoint.
type UnixSocketServer struct {
	socketPath string
	processor  AlertProcessor
	metrics    *Metrics
	listener   net.Listener
	mu         sync.Mutex
	closed     bool
	wg         sync.WaitGroup
	quit       chan struct{}
}

// NewUnixSocketServer constructs a new Unix domain socket server instance.
func NewUnixSocketServer(socketPath string, processor AlertProcessor, metrics *Metrics) *UnixSocketServer {
	return &UnixSocketServer{
		socketPath: socketPath,
		processor:  processor,
		metrics:    metrics,
		quit:       make(chan struct{}),
	}
}

// SocketPath returns the configured filesystem path for the socket.
func (s *UnixSocketServer) SocketPath() string {
	return s.socketPath
}

// Start opens the Unix domain socket, applies POSIX 0660 permissions, and begins accepting connections.
func (s *UnixSocketServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return errors.New("unix socket server already started")
	}

	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory for socket %s: %w", s.socketPath, err)
	}

	// Clean up stale socket file if not currently in active use
	if _, err := os.Stat(s.socketPath); err == nil {
		conn, dialErr := net.DialTimeout("unix", s.socketPath, 100*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return fmt.Errorf("unix socket %s already in active use by another process", s.socketPath)
		}
		_ = os.Remove(s.socketPath)
	}

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket %s: %w", s.socketPath, err)
	}

	// Strict POSIX 0660 file permissions
	if err := os.Chmod(s.socketPath, 0660); err != nil {
		l.Close()
		_ = os.Remove(s.socketPath)
		return fmt.Errorf("failed to chmod 0660 unix socket %s: %w", s.socketPath, err)
	}

	s.listener = l
	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

func (s *UnixSocketServer) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				// Transient or listener closed error
				return
			}
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(conn)
	}
}

func (s *UnixSocketServer) handleConn(conn net.Conn) {
	defer conn.Close()

	// Extract peer credentials on Linux systems using SO_PEERCRED
	peerPID, peerUID, peerGID := -1, -1, -1
	if unixConn, ok := conn.(*net.UnixConn); ok {
		if rawConn, err := unixConn.SyscallConn(); err == nil {
			_ = rawConn.Control(func(fd uintptr) {
				ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
				if err == nil && ucred != nil {
					peerPID = int(ucred.Pid)
					peerUID = int(ucred.Uid)
					peerGID = int(ucred.Gid)
				}
			})
		}
	}

	// Read alert payload with 1MB ceiling per DESIGN.md
	var alert model.Alert
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&alert); err != nil {
		errResp := &engine.RemediationResult{
			FinalState: model.StateEscalated,
			Error:      fmt.Sprintf("malformed alert JSON: %v", err),
		}
		_ = json.NewEncoder(conn).Encode(errResp)
		return
	}

	if alert.ID == "" {
		alert.ID = fmt.Sprintf("sock-%d", time.Now().UnixNano())
	}
	if alert.Source == "" {
		alert.Source = "unix_socket"
	}
	if alert.ReceivedAt.IsZero() {
		alert.ReceivedAt = time.Now().UTC()
	}
	if alert.Annotations == nil {
		alert.Annotations = make(map[string]string)
	}
	if peerUID != -1 {
		alert.Annotations["peer_uid"] = strconv.Itoa(peerUID)
		alert.Annotations["peer_gid"] = strconv.Itoa(peerGID)
		alert.Annotations["peer_pid"] = strconv.Itoa(peerPID)
	}

	res, _ := s.processor.ProcessAlert(&alert)
	if s.metrics != nil && res != nil {
		s.metrics.RecordRemediationResult(res)
	}

	_ = json.NewEncoder(conn).Encode(res)
}

// Stop gracefully shuts down the listener, closes active connections, and unlinks the socket file.
func (s *UnixSocketServer) Stop() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.quit)

	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
	_ = os.Remove(s.socketPath)
	return err
}
