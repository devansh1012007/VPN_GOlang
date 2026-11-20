// Package api implements the admin REST API (ADR-004): /api/v1 endpoints,
// loopback-bound http.Server with hard timeouts, bearer-token auth.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/devansh1012007/VPN_GOlang/internal/auth"
	"github.com/devansh1012007/VPN_GOlang/internal/logging"
	"github.com/devansh1012007/VPN_GOlang/internal/store"
	"github.com/devansh1012007/VPN_GOlang/internal/wireguard"
)

// Backend is what the API needs from the server orchestrator. The interface
// keeps handlers testable against a fake (AGENTS.md testing requirements).
type Backend interface {
	AddPeer(name, publicKey string) (*wireguard.Peer, error)
	GetPeer(id string) (*wireguard.Peer, error)
	ListPeers() ([]wireguard.Peer, error)
	RemovePeer(id string) error
	Status() (*StatusReport, error)
}

// StatusReport is the /status payload.
type StatusReport struct {
	Interface     string     `json:"interface"`
	ListenPort    int        `json:"listen_port"`
	PublicKey     string     `json:"public_key"`
	Subnet        string     `json:"subnet"`
	PeerCount     int        `json:"peer_count"`
	Peers         []PeerLive `json:"peers"`
	UptimeSeconds int64      `json:"uptime_seconds"`
}

// PeerLive is per-peer live state in /status.
type PeerLive struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	PublicKey     string `json:"public_key"`
	Address       string `json:"address"`
	Endpoint      string `json:"endpoint,omitempty"`
	LastHandshake string `json:"last_handshake,omitempty"`
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
}

// APIError is the JSON error envelope.
type APIError struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// ServerConfig configures the API server.
type ServerConfig struct {
	// Addr is the listen address, e.g. "127.0.0.1:8080".
	Addr string
	// Authenticator validates bearer tokens.
	Authenticator auth.Authenticator
	// Backend serves domain operations.
	Backend Backend
	// ReadTimeout / WriteTimeout / IdleTimeout (from config.API.Timeouts()).
	ReadTimeout, WriteTimeout, IdleTimeout time.Duration
	// Logger (optional; default is a stderr logger).
	Logger *logging.Logger
	// StartedAt powers uptime_seconds in /status.
	StartedAt time.Time
}

// Server is the REST API server.
type Server struct {
	cfg   ServerConfig
	httpd *http.Server
}

// NewServer wires routes. No listener is opened here (open happens in Start).
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("api: listen address required")
	}
	if cfg.Authenticator == nil {
		return nil, fmt.Errorf("api: authenticator required")
	}
	if cfg.Backend == nil {
		return nil, fmt.Errorf("api: backend required")
	}
	if cfg.ReadTimeout <= 0 || cfg.WriteTimeout <= 0 || cfg.IdleTimeout <= 0 {
		return nil, fmt.Errorf("api: all http timeouts must be positive")
	}
	if cfg.Logger == nil {
		cfg.Logger = logging.Noop()
	}
	if cfg.StartedAt.IsZero() {
		cfg.StartedAt = time.Now()
	}
	s := &Server{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", s.auth(s.handleStatus))
	mux.HandleFunc("/api/v1/peers", s.auth(s.handlePeers))
	mux.HandleFunc("/api/v1/peers/", s.auth(s.handlePeerItem))
	s.httpd = &http.Server{
		Addr:         cfg.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}
	return s, nil
}

// Start begins serving; it blocks until Shutdown is called or the listener
// errors.
func (s *Server) Start() error {
	s.cfg.Logger.Info("api listening", "addr", s.cfg.Addr)
	return s.httpd.ListenAndServe()
}

// Shutdown drains connections gracefully (server orchestrator calls this on
// SIGTERM — ADR-006).
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpd.Shutdown(ctx)
}

// auth wraps a handler with token validation (ADR-004; SR-3).
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if !s.cfg.Authenticator.Authenticate(token) {
			s.cfg.Logger.Warn("api auth failed",
				"remote", r.RemoteAddr, "method", r.Method, "path", r.URL.Path)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// bearerToken extracts "Bearer <tok>" from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rep, err := s.cfg.Backend.Status()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "status unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		peers, err := s.cfg.Backend.ListPeers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"peers": peers})
	case http.MethodPost:
		var req struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body", err.Error())
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.PublicKey = strings.TrimSpace(req.PublicKey)
		if req.PublicKey == "" {
			writeError(w, http.StatusBadRequest, "public_key required")
			return
		}
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "name required")
			return
		}
		peer, err := s.cfg.Backend.AddPeer(req.Name, req.PublicKey)
		if err != nil {
			writeError(w, http.StatusConflict, "add peer failed", err.Error())
			return
		}
		s.cfg.Logger.Info("api peer added", "peer_id", peer.ID, "name", peer.Name)
		writeJSON(w, http.StatusCreated, peer)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handlePeerItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/peers/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "peer id required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		peer, err := s.cfg.Backend.GetPeer(id)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "peer not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "get failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, peer)
	case http.MethodDelete:
		if err := s.cfg.Backend.RemovePeer(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "peer not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "remove failed", err.Error())
			return
		}
		s.cfg.Logger.Info("api peer removed", "peer_id", id)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string, details ...string) {
	e := APIError{Error: msg}
	if len(details) > 0 {
		e.Details = details[0]
	}
	writeJSON(w, code, e)
}
