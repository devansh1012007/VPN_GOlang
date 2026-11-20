// Package wireguard wraps the wgctrl control plane (ADR-002).
//
// The DeviceManager interface keeps wgctrl as an injectable adapter so tests
// run against a fake client — unit tests never touch a live interface
// (constraint: no live network mutation from dev machines).
package wireguard

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DeviceConfig is the desired state of a WireGuard device.
type DeviceConfig struct {
	Name       string
	PrivateKey string // base64, generated via wgtypes.GeneratePrivateKey
	ListenPort int
	// Peers is the full desired peer set; Reconcile makes the device match it.
	Peers []PeerConfig
}

// PeerConfig is one desired peer entry.
type PeerConfig struct {
	PublicKey  string   // base64
	AllowedIPs []string // e.g. ["10.100.0.5/32"]
}

// DeviceStatus is the observed state reported back to operators.
type DeviceStatus struct {
	Name       string
	ListenPort int
	PublicKey  string
	Peers      []PeerStatus
}

// PeerStatus is the observed per-peer state.
type PeerStatus struct {
	PublicKey       string
	Endpoint        string
	AllowedIPs      []string
	LastHandshake   time.Time // zero = never
	TransferRxBytes int64
	TransferTxBytes int64
}

// DeviceManager programs WireGuard devices. All methods are idempotent where
// meaningful (ADR-006).
type DeviceManager interface {
	// ConfigureDevice makes the device's key/port/peer set match cfg
	// (add/update/remove as needed).
	ConfigureDevice(cfg DeviceConfig) error
	// Status reads back the device state.
	Status(name string) (*DeviceStatus, error)
	// RemovePeer removes a single peer by public key.
	RemovePeer(deviceName, publicKey string) error
	// Close releases the underlying client.
	Close() error
}

// Manager is the wgctrl-backed DeviceManager (the only real implementation).
type Manager struct {
	client wgctrlClient
}

// wgctrlClient is the subset of wgctrl.Client we use (enables the fake).
type wgctrlClient interface {
	Device(name string) (*wgtypes.Device, error)
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Close() error
}

// NewManager builds a Manager bound to the real wgctrl client.
// The caller is responsible for having CAP_NET_ADMIN; this constructor does
// not mutate anything (creating the client opens a netlink socket only).
func NewManager() (*Manager, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl client: %w", err)
	}
	return &Manager{client: c}, nil
}

// NewManagerWithClient injects a client (used by tests and by wireguard-go
// userspace sockets via wgctrl.NewClientConfigs).
func NewManagerWithClient(c wgctrlClient) *Manager {
	return &Manager{client: c}
}

// ConfigureDevice reconciles the desired config onto the device.
func (m *Manager) ConfigureDevice(cfg DeviceConfig) error {
	key, err := ParseKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("device %s private key: %w", cfg.Name, err)
	}
	wc := wgtypes.Config{
		PrivateKey: &key,
	}
	if cfg.ListenPort > 0 {
		port := cfg.ListenPort
		wc.ListenPort = &port
	}
	// Full desired peer list: remove everything not present, upsert the rest.
	want := make(map[string]PeerConfig, len(cfg.Peers))
	for _, p := range cfg.Peers {
		want[p.PublicKey] = p
	}
	current, err := m.client.Device(cfg.Name)
	if err != nil {
		return fmt.Errorf("read device %s: %w", cfg.Name, err)
	}
	for _, existing := range current.Peers {
		if _, keep := want[existing.PublicKey.String()]; !keep {
			pk := existing.PublicKey
			// Remove via zero-address replace (canonical way: replace peer
			// with AllowedIPs removed and RemovePeer=true).
			wc.Peers = append(wc.Peers, wgtypes.PeerConfig{
				PublicKey: pk,
				Remove:    true,
			})
		}
	}
	for _, p := range cfg.Peers {
		pk, err := ParseKey(p.PublicKey)
		if err != nil {
			return fmt.Errorf("peer key: %w", err)
		}
		ips := make([]net.IPNet, 0, len(p.AllowedIPs))
		for _, s := range p.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(s)
			if err != nil {
				return fmt.Errorf("peer allowed ip %q: %w", s, err)
			}
			ips = append(ips, *ipnet)
		}
		wc.Peers = append(wc.Peers, wgtypes.PeerConfig{
			PublicKey:  pk,
			AllowedIPs: ips,
		})
	}
	if err := m.client.ConfigureDevice(cfg.Name, wc); err != nil {
		return fmt.Errorf("configure device %s: %w", cfg.Name, err)
	}
	return nil
}

// RemovePeer removes one peer from the device.
func (m *Manager) RemovePeer(deviceName, publicKey string) error {
	key, err := ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("peer key: %w", err)
	}
	return m.client.ConfigureDevice(deviceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}},
	})
}

// Status reads device state back.
func (m *Manager) Status(name string) (*DeviceStatus, error) {
	dev, err := m.client.Device(name)
	if err != nil {
		return nil, fmt.Errorf("read device %s: %w", name, err)
	}
	st := &DeviceStatus{
		Name:       dev.Name,
		ListenPort: dev.ListenPort,
		PublicKey:  dev.PublicKey.String(),
	}
	for _, p := range dev.Peers {
		ps := PeerStatus{
			PublicKey:       p.PublicKey.String(),
			AllowedIPs:      make([]string, 0, len(p.AllowedIPs)),
			LastHandshake:   p.LastHandshakeTime,
			TransferRxBytes: p.ReceiveBytes,
			TransferTxBytes: p.TransmitBytes,
		}
		if p.Endpoint != nil {
			ps.Endpoint = p.Endpoint.String()
		}
		for _, ip := range p.AllowedIPs {
			ps.AllowedIPs = append(ps.AllowedIPs, ip.String())
		}
		st.Peers = append(st.Peers, ps)
	}
	return st, nil
}

// Close releases the netlink client.
func (m *Manager) Close() error { return m.client.Close() }
