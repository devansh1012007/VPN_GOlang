package wireguard

// Peer model and key utilities. All key generation and parsing goes through
// wgtypes (wgctrl) — this project never implements its own crypto
// (MASTER_PROMPT constraint #1, ADR-001 compliance).

import (
	"fmt"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer is the platform's persisted peer record (ADR-005 store payload).
type Peer struct {
	// ID is a short, stable, URL-safe identifier for the peer.
	ID string `json:"id"`
	// Name is the human label, e.g. "laptop".
	Name string `json:"name"`
	// PublicKey (base64). The corresponding private key lives only on the peer.
	PublicKey string `json:"public_key"`
	// Address is the peer's VPN address with mask, e.g. "10.100.0.5/32".
	Address string `json:"address"`
	// CreatedAt / UpdatedAt are lifecycle timestamps.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AllowedIPs returns the address split into a one-element list, canonical
// form for client peers on a server-managed wg device.
func (p *Peer) AllowedIPs() []string {
	if p.Address == "" {
		return nil
	}
	return []string{p.Address}
}

// ParseKey parses a base64 WireGuard key via wgtypes (canonical source).
func ParseKey(s string) (wgtypes.Key, error) {
	k, err := wgtypes.ParseKey(strings.TrimSpace(s))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("parse wireguard key: %w", err)
	}
	return k, nil
}

// GeneratePrivateKey generates a fresh WireGuard private key via wgtypes
// (curve25519, clamped, random-sourced by the library — no custom RNG here).
func GeneratePrivateKey() (string, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("generate private key: %w", err)
	}
	return k.String(), nil
}

// PublicKeyOf derives the public key of a base64 private key via wgtypes.
func PublicKeyOf(privateKey string) (string, error) {
	k, err := ParseKey(privateKey)
	if err != nil {
		return "", err
	}
	pub := k.PublicKey()
	return pub.String(), nil
}

// KeyFingerprint returns a short non-sensitive handle for logs (first 8 hex
// nibbles of the base64 public key). Never returns key material itself.
func KeyFingerprint(publicKey string) string {
	if len(publicKey) < 8 {
		return "<invalid>"
	}
	return publicKey[:8]
}
