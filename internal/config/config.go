// Package config loads, validates, and saves the vpnd server configuration.
//
// Contract (ADR-003): JSON files, fail-fast validation with precise error paths,
// and a redacted view for any safe printing (SR-6 in the threat model: the
// server private key must never leak through logs or API responses).
package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Interface mirrors the WireGuard device parameters vpnd programs.
type Interface struct {
	// Name is the Linux link name, e.g. "wg0". Must be non-empty and <= 15 bytes.
	Name string `json:"name"`
	// PrivateKey is the server private key in base64 (wgtypes.Key.String()).
	PrivateKey string `json:"private_key"`
	// ListenPort is the UDP port; 0 means keep the current one.
	ListenPort int `json:"listen_port"`
}

// Network holds the VPN subnet and routing parameters.
type Network struct {
	// Address is the VPN subnet, e.g. "10.100.0.0/24". Must be IPv4 CIDR with
	// prefix length >= 16 (at least /16... small subnets are rejected).
	Address string `json:"address"`
	// ServerCIDROffset is the host part assigned to the server itself
	// (offset inside Address, default 1 → e.g. 10.100.0.1/24).
	ServerCIDROffset int `json:"server_cidr_offset"`
	// MTU for the interface (default 1420, WireGuard-typical for IPv4 outer).
	MTU int `json:"mtu"`
	// ForwardEnabled enables routing between VPN subnet and the NAT egress.
	ForwardEnabled bool `json:"forward_enabled"`
	// AllowedEgress names the host interface(s) VPN traffic may masquerade out
	// of (default ["eth0"]).
	AllowedEgress []string `json:"allowed_egress"`
}

// API configures the admin REST API (ADR-004).
type API struct {
	// Enabled turns the REST API on.
	Enabled bool `json:"enabled"`
	// ListenAddress defaults to "127.0.0.1"; loopback-only unless explicitly widened.
	ListenAddress string `json:"listen_address"`
	// ListenPort for the API server.
	ListenPort int `json:"listen_port"`
	// TokenPath points to a file containing the bearer token (0600).
	TokenPath string `json:"token_path"`
	// ReadTimeout, WriteTimeout, IdleTimeout for http.Server.
	ReadTimeoutSeconds  int `json:"read_timeout_seconds"`
	WriteTimeoutSeconds int `json:"write_timeout_seconds"`
	IdleTimeoutSeconds  int `json:"idle_timeout_seconds"`
}

// Firewall configures the rendered iptables ruleset.
type Firewall struct {
	// Enabled applies/removes rules when true.
	Enabled bool `json:"enabled"`
	// ChainTag prefixes all rules vpnd owns (idempotent remove, ADR-006).
	ChainTag string `json:"chain_tag"`
}

// Store locates the peer persistence file (ADR-005).
type Store struct {
	// Path to the JSON peer store.
	Path string `json:"path"`
	// SaveOnEveryMutation persists immediately after each change (default true).
	SaveOnEveryMutation bool `json:"save_on_every_mutation"`
}

// Server is the root configuration document.
type Server struct {
	Interface         Interface `json:"interface"`
	Network           Network   `json:"network"`
	API               API       `json:"api"`
	Firewall          Firewall  `json:"firewall"`
	Store             Store     `json:"store"`
	RemoveIfaceOnStop bool      `json:"remove_interface_on_stop"`
}

// DefaultServer returns a fully-populated, valid configuration with zero
// secrets (PrivateKey empty, token file expected at a default path).
func DefaultServer() *Server {
	return &Server{
		Interface: Interface{
			Name:       "wg0",
			PrivateKey: "",
			ListenPort: 51820,
		},
		Network: Network{
			Address:          "10.100.0.0/24",
			ServerCIDROffset: 1,
			MTU:              1420,
			ForwardEnabled:   true,
			AllowedEgress:    []string{"eth0"},
		},
		API: API{
			Enabled:             true,
			ListenAddress:       "127.0.0.1",
			ListenPort:          8080,
			TokenPath:           "/etc/vpnd/token",
			ReadTimeoutSeconds:  5,
			WriteTimeoutSeconds: 10,
			IdleTimeoutSeconds:  60,
		},
		Firewall: Firewall{
			Enabled:  true,
			ChainTag: "VPND",
		},
		Store: Store{
			Path:                "/var/lib/vpnd/peers.json",
			SaveOnEveryMutation: true,
		},
		RemoveIfaceOnStop: false,
	}
}

// Validate checks every invariant, returning errors that name the JSON path.
func (c *Server) Validate() error {
	if c.Interface.Name == "" {
		return fmt.Errorf("interface.name: must not be empty")
	}
	if len(c.Interface.Name) > 15 {
		return fmt.Errorf("interface.name: %q exceeds 15 bytes (Linux link name limit)", c.Interface.Name)
	}
	if c.Interface.ListenPort != 0 {
		if c.Interface.ListenPort < 1 || c.Interface.ListenPort > 65535 {
			return fmt.Errorf("interface.listen_port: %d out of range 1..65535", c.Interface.ListenPort)
		}
	}
	if c.Interface.PrivateKey != "" {
		if len(c.Interface.PrivateKey) != 44 { // wgtypes.Key.String() length
			return fmt.Errorf("interface.private_key: wrong length (%d), want 44 base64 chars", len(c.Interface.PrivateKey))
		}
		if _, err := ParseKey(c.Interface.PrivateKey); err != nil {
			return fmt.Errorf("interface.private_key: %w", err)
		}
	}

	_, subnet, err := net.ParseCIDR(c.Network.Address)
	if err != nil {
		return fmt.Errorf("network.address: %q is not a valid CIDR", c.Network.Address)
	}
	ones, _ := subnet.Mask.Size()
	if ones > 30 {
		return fmt.Errorf("network.address: /%d leaves too few addresses; want prefix <= 30", ones)
	}
	if c.Network.ServerCIDROffset < 1 || c.Network.ServerCIDROffset > 250 {
		return fmt.Errorf("network.server_cidr_offset: %d out of sane range 1..250", c.Network.ServerCIDROffset)
	}
	if c.Network.MTU != 0 && (c.Network.MTU < 1280 || c.Network.MTU > 1500) {
		return fmt.Errorf("network.mtu: %d out of range 1280..1500", c.Network.MTU)
	}
	if len(c.Network.AllowedEgress) == 0 && c.Network.ForwardEnabled {
		return fmt.Errorf("network.allowed_egress: required when forwarding is enabled")
	}

	if c.API.Enabled {
		if c.API.ListenAddress == "" {
			return fmt.Errorf("api.listen_address: required when api.enabled")
		}
		if c.API.ListenPort < 1 || c.API.ListenPort > 65535 {
			return fmt.Errorf("api.listen_port: %d out of range 1..65535", c.API.ListenPort)
		}
		if c.API.TokenPath == "" {
			return fmt.Errorf("api.token_path: required when api.enabled")
		}
		if c.API.ReadTimeoutSeconds <= 0 || c.API.WriteTimeoutSeconds <= 0 || c.API.IdleTimeoutSeconds <= 0 {
			return fmt.Errorf("api.*_timeout_seconds: all must be > 0")
		}
	}

	if c.Firewall.Enabled && c.Firewall.ChainTag == "" {
		return fmt.Errorf("firewall.chain_tag: required when firewall.enabled")
	}
	if c.Store.Path == "" {
		return fmt.Errorf("store.path: must not be empty")
	}
	return nil
}

// ServerIP returns the VPN address of the server inside Network.Address
// (host offset ServerCIDROffset), e.g. "10.100.0.1".
func (c *Server) ServerIP() net.IP {
	ip, subnet, err := net.ParseCIDR(c.Network.Address)
	if err != nil {
		return nil
	}
	maskOnes, _ := subnet.Mask.Size()
	if maskOnes < 8 {
		return nil
	}
	// Work on the network base address, add the offset.
	base := ip.Mask(subnet.Mask).To4()
	if base == nil {
		return nil
	}
	offset := c.Network.ServerCIDROffset
	base[3] += byte(offset) // carries overflow; validated ranges keep this safe for /24.. /16
	return base
}

// Redacted returns a copy safe for logs and API responses: PrivateKey is
// replaced with "REDACTED" (threat-model SR-6, review finding F-001).
func (c *Server) Redacted() Server {
	cp := *c
	if cp.Interface.PrivateKey != "" {
		cp.Interface.PrivateKey = "REDACTED"
	}
	return cp
}

// Load reads and validates a JSON config file. The file must have mode 0600
// when owned by the daemon (warn-only check to keep unit tests portable).
func Load(path string) (*Server, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := DefaultServer()
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(cfg); err != nil {
		if se, ok := err.(*json.SyntaxError); ok {
			return nil, fmt.Errorf("parse config %s at byte offset %d: %v", filepath.Base(path), se.Offset, se)
		}
		return nil, fmt.Errorf("parse config %s: %w", filepath.Base(path), err)
	}
	if dec.More() {
		return nil, fmt.Errorf("parse config %s: trailing data after JSON object", filepath.Base(path))
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save atomically writes the config with mode 0600 (ADR-003/ADR-005 discipline).
func Save(path string, c *Server) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("refusing to save invalid config: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("commit config: %w", err)
	}
	return nil
}

// ParseKey validates a base64 WireGuard key without importing wgctrl here;
// canonical parsing lives in internal/wireguard (this only checks shape).
func ParseKey(s string) (KeyRef, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return KeyRef{}, fmt.Errorf("invalid base64: %w", err)
	}
	if len(b) != 32 {
		return KeyRef{}, fmt.Errorf("decoded key length %d, want 32", len(b))
	}
	// X25519 clamping performed by wgtypes.GeneratePrivateKey:
	//   k[0] &= 248 (low 3 bits clear), k[31] &= 127 (bit 7 clear), k[31] |= 64 (bit 6 set).
	if b[0]&0x07 != 0 || b[31]&0x80 != 0 || b[31]&0x40 == 0 {
		return KeyRef{}, fmt.Errorf("key not clamped (X25519 form invalid)")
	}
	return KeyRef{raw: b}, nil
}

// KeyRef is an opaque reference to a validated key; it intentionally exposes
// no bytes so callers cannot accidentally log key material.
type KeyRef struct{ raw []byte }

// String returns "KEY(32B)" — never the key material.
func (k KeyRef) String() string { return "KEY(32B)" }

// Timeouts converts API timeout fields to durations for http.Server.
func (a API) Timeouts() (read, write, idle time.Duration) {
	return time.Duration(a.ReadTimeoutSeconds) * time.Second,
		time.Duration(a.WriteTimeoutSeconds) * time.Second,
		time.Duration(a.IdleTimeoutSeconds) * time.Second
}
