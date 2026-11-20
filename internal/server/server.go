// Package server is the vpnd orchestrator: it owns the lifecycle (apply,
// reconcile, reload, teardown) and implements the api.Backend contract.
package server

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devansh1012007/VPN_GOlang/internal/api"
	"github.com/devansh1012007/VPN_GOlang/internal/config"
	"github.com/devansh1012007/VPN_GOlang/internal/logging"
	"github.com/devansh1012007/VPN_GOlang/internal/network"
	"github.com/devansh1012007/VPN_GOlang/internal/store"
	"github.com/devansh1012007/VPN_GOlang/internal/wireguard"
)

// DeviceManager is the wg control plane (redeclared from wireguard so the
// orchestrator can be tested with a fake — see wireguard.DeviceManager).
type DeviceManager interface {
	ConfigureDevice(cfg wireguard.DeviceConfig) error
	Status(name string) (*wireguard.DeviceStatus, error)
	RemovePeer(deviceName, publicKey string) error
	Close() error
}

// Options injects collaborators; tests pass fakes, production passes the real
// implementations (see cmd/vpnd).
type Options struct {
	Logger   *logging.Logger
	Devices  DeviceManager
	Links    network.LinkManager
	FwRunner network.CommandRunner
	Sysctl   *network.Sysctl
	// Now is the clock (tests inject a fixed one).
	Now func() time.Time
}

// Server is the orchestrator. It implements api.Backend.
type Server struct {
	cfg       *config.Server
	opts      Options
	log       *logging.Logger
	store     store.Store
	ipam      *network.IPAM
	mu        sync.Mutex
	startedAt time.Time
}

// New builds the orchestrator. It performs NO host mutation: mutations happen
// only in Apply() (ADR-006 — construction is side-effect free).
func New(cfg *config.Server, peerStore store.Store, opts Options) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("server: config required")
	}
	if peerStore == nil {
		return nil, fmt.Errorf("server: peer store required")
	}
	if opts.Devices == nil {
		return nil, fmt.Errorf("server: device manager required")
	}
	if opts.Links == nil {
		return nil, fmt.Errorf("server: link manager required")
	}
	if opts.FwRunner == nil {
		return nil, fmt.Errorf("server: firewall runner required")
	}
	if opts.Sysctl == nil {
		return nil, fmt.Errorf("server: sysctl manager required")
	}
	if opts.Logger == nil {
		opts.Logger = logging.Noop()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	ipam, err := network.NewIPAM(cfg.Network.Address)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	// Rebuild allocations from the persisted store (crash-safe reconcile).
	addrs, err := peerStore.AllocatedAddresses()
	if err != nil {
		return nil, fmt.Errorf("server: restore allocations: %w", err)
	}
	for _, a := range addrs {
		off, err := ipam.OffsetForIP(network.NormalizeIP(a))
		if err != nil {
			return nil, fmt.Errorf("server: stored peer address %s invalid: %w", a, err)
		}
		if _, err := ipam.Reserve(off); err != nil {
			return nil, fmt.Errorf("server: double-booked address %s in store", a)
		}
	}
	return &Server{
		cfg: cfg, opts: opts, log: opts.Logger, store: peerStore, ipam: ipam,
		startedAt: opts.Now(),
	}, nil
}

// IPAM exposes the allocator (for diagnostics; not used by the API).
func (s *Server) IPAMState() string { return s.ipam.String() }

// Apply brings the whole desired state up: sysctls, link, firewall, device.
// It is the idempotent "make it so" entry point (run on start and on reload).
func (s *Server) Apply() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.Network.ForwardEnabled {
		if _, err := s.opts.Sysctl.EnsureForwarding(); err != nil {
			return fmt.Errorf("server: forwarding sysctl: %w", err)
		}
	}
	serverCIDR := fmt.Sprintf("%s/%s", network.NormalizeIP(s.cfg.ServerIP().String()), maskOf(s.cfg.Network.Address))
	if err := s.opts.Links.EnsureLink(s.cfg.Interface.Name, serverCIDR, s.cfg.Network.MTU); err != nil {
		return fmt.Errorf("server: ensure link: %w", err)
	}
	if s.cfg.Firewall.Enabled {
		fw, err := s.firewall()
		if err != nil {
			return err
		}
		if err := fw.Apply(); err != nil {
			return fmt.Errorf("server: firewall: %w", err)
		}
	}
	return s.reconcileDevice()
}

// TearDown removes what Apply created (firewall rules; optionally the link).
// Idempotent; safe to call when partially applied.
func (s *Server) TearDown() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	if s.cfg.Firewall.Enabled {
		if fw, err := s.firewall(); err == nil {
			if err := fw.Remove(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("server: firewall remove: %w", err)
			}
		} else if firstErr == nil {
			firstErr = fmt.Errorf("server: firewall construct: %w", err)
		}
	}
	if s.cfg.RemoveIfaceOnStop {
		if err := s.opts.Links.RemoveLink(s.cfg.Interface.Name); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("server: link remove: %w", err)
		}
	}
	return firstErr
}

// reconcileDevice pushes store state onto the wg device (add missing peers).
// It never removes unknown device peers that are not in the store — that
// reconciliation is explicit via ConfigureDevice with the full set.
func (s *Server) reconcileDevice() error {
	peers, err := s.store.List()
	if err != nil {
		return fmt.Errorf("server: list peers: %w", err)
	}
	desired := make([]wireguard.PeerConfig, 0, len(peers))
	for _, p := range peers {
		desired = append(desired, wireguard.PeerConfig{
			PublicKey:  p.PublicKey,
			AllowedIPs: p.AllowedIPs(),
		})
	}
	cfg := wireguard.DeviceConfig{
		Name:       s.cfg.Interface.Name,
		PrivateKey: s.cfg.Interface.PrivateKey,
		ListenPort: s.cfg.Interface.ListenPort,
		Peers:      desired,
	}
	if err := s.opts.Devices.ConfigureDevice(cfg); err != nil {
		return fmt.Errorf("server: configure device: %w", err)
	}
	return nil
}

// firewall builds the Firewall from config (no mutation).
func (s *Server) firewall() (*network.Firewall, error) {
	return network.NewFirewall(network.FirewallSpec{
		Interface:    s.cfg.Interface.Name,
		Subnet:       s.cfg.Network.Address,
		EgressIfaces: s.cfg.Network.AllowedEgress,
		ServerIP:     network.NormalizeIP(s.cfg.ServerIP().String()),
		ChainTag:     s.cfg.Firewall.ChainTag,
	}, s.opts.FwRunner)
}

// ---- api.Backend implementation ----

// AddPeer validates and registers a new peer end-to-end.
func (s *Server) AddPeer(name, publicKey string) (*wireguard.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" {
		return nil, fmt.Errorf("server: peer name required")
	}
	if _, err := wireguard.ParseKey(publicKey); err != nil {
		return nil, fmt.Errorf("server: public key invalid: %w", err)
	}
	if _, err := s.store.GetByKey(publicKey); err == nil {
		return nil, fmt.Errorf("server: public key already registered")
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("server: store lookup: %w", err)
	}
	_, addr, err := s.ipam.Allocate()
	if err != nil {
		return nil, fmt.Errorf("server: address pool exhausted: %w", err)
	}
	now := s.opts.Now().UTC()
	p := wireguard.Peer{
		ID:        newPeerID(now),
		Name:      name,
		PublicKey: publicKey,
		Address:   addr,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.Add(p); err != nil {
		s.ipam.Release(offOf(addr)) // roll back allocation on store failure
		return nil, fmt.Errorf("server: persist peer: %w", err)
	}
	if err := s.reconcileDevice(); err != nil {
		// Device programming failed: roll the store back so state stays
		// consistent (F-002 discipline: never leave half-applied peers).
		s.store.Delete(p.ID)
		s.ipam.Release(offOf(addr))
		return nil, fmt.Errorf("server: program peer: %w", err)
	}
	s.log.Info("peer added", "peer_id", p.ID, "name", p.Name, "address", p.Address)
	return &p, nil
}

// GetPeer returns a persisted peer.
func (s *Server) GetPeer(id string) (*wireguard.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Get(id)
}

// ListPeers returns all persisted peers.
func (s *Server) ListPeers() ([]wireguard.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.List()
}

// RemovePeer removes the peer from the device FIRST, then from the store
// (F-002: a store entry must never point at a still-programmed device peer
// if the operation half-failed; the reverse ordering would).
func (s *Server) RemovePeer(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.store.Get(id)
	if err != nil {
		return err
	}
	if err := s.opts.Devices.RemovePeer(s.cfg.Interface.Name, p.PublicKey); err != nil {
		return fmt.Errorf("server: remove device peer: %w", err)
	}
	if _, err := s.store.Delete(id); err != nil {
		return fmt.Errorf("server: delete stored peer: %w", err)
	}
	s.ipam.Release(offOf(p.Address))
	s.log.Info("peer removed", "peer_id", p.ID)
	return nil
}

// Status merges device and store state for /api/v1/status.
func (s *Server) Status() (*api.StatusReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := &api.StatusReport{
		Interface:     s.cfg.Interface.Name,
		ListenPort:    s.cfg.Interface.ListenPort,
		Subnet:        s.cfg.Network.Address,
		UptimeSeconds: int64(s.opts.Now().Sub(s.startedAt).Seconds()),
	}
	peers, err := s.store.List()
	if err != nil {
		return nil, fmt.Errorf("server: list peers: %w", err)
	}
	rep.PeerCount = len(peers)
	devStatus, err := s.opts.Devices.Status(s.cfg.Interface.Name)
	if err == nil {
		rep.PublicKey = devStatus.PublicKey
		rep.ListenPort = devStatus.ListenPort
		byKey := map[string]api.PeerLive{}
		for _, ps := range devStatus.Peers {
			byKey[ps.PublicKey] = api.PeerLive{
				PublicKey:     ps.PublicKey,
				Endpoint:      ps.Endpoint,
				Address:       "",
				LastHandshake: ps.LastHandshake.Format(time.RFC3339),
				RxBytes:       ps.TransferRxBytes,
				TxBytes:       ps.TransferTxBytes,
			}
		}
		for _, p := range peers {
			live := byKey[p.PublicKey]
			live.ID = p.ID
			live.Name = p.Name
			live.Address = p.Address
			rep.Peers = append(rep.Peers, live)
		}
	} else {
		// device unavailable (e.g. interface down): still report store view
		for _, p := range peers {
			rep.Peers = append(rep.Peers, api.PeerLive{
				ID: p.ID, Name: p.Name, PublicKey: p.PublicKey, Address: p.Address,
			})
		}
	}
	return rep, nil
}

// Store returns the peer store (used by cmd/vpnd wiring and tests).
func (s *Server) Store() store.Store { return s.store }

// helpers

// maskOf extracts the mask string of a CIDR ("10.100.0.0/24" → "24").
func maskOf(cidr string) string {
	for i := len(cidr) - 1; i >= 0; i-- {
		if cidr[i] == '/' {
			return cidr[i+1:]
		}
	}
	return "32"
}

// offOf maps a peer address ("10.100.0.42/32") to its IPAM host offset.
// Defensive: returns 0 (which Release ignores) for malformed input.
func offOf(addr string) int {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	if i := strings.LastIndexByte(addr, '.'); i >= 0 {
		addr = addr[i+1:]
	}
	n, err := strconv.Atoi(addr)
	if err != nil {
		return 0
	}
	return n
}

// peerSeq guarantees ID uniqueness even when the clock stalls between two
// serialized AddPeer calls.
var peerSeq atomic.Uint64

// newPeerID builds a sortable, URL-safe id: unix-nanos hex + sequence.
func newPeerID(t time.Time) string {
	return fmt.Sprintf("p%x-%d", t.UnixNano(), peerSeq.Add(1))
}
