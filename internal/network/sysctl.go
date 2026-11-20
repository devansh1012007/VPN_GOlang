package network

import (
	"fmt"
	"os"
	"strings"
)

// Sysctl manages kernel parameters required for VPN forwarding. Writes go
// through the procfs path only; no shell is involved (ADR-006).
//
// IMPORTANT (constraint #2): Set() mutates host kernel state. Unit tests only
// exercise TempDir-backed paths, never /proc/sys.
type Sysctl struct {
	// Root overrides "/proc/sys" for testing.
	Root string
}

// ForwardingParams lists the parameters vpnd needs for routing.
var ForwardingParams = []string{
	"net/ipv4/ip_forward",
}

// Get reads a parameter value.
func (s *Sysctl) Get(param string) (string, error) {
	path := s.pathFor(param)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("sysctl get %s: %w", param, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// Set writes a parameter value.
func (s *Sysctl) Set(param, value string) error {
	path := s.pathFor(param)
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		return fmt.Errorf("sysctl set %s=%s: %w", param, value, err)
	}
	return nil
}

// EnsureForwarding enables IPv4 forwarding idempotently; returns whether a
// write actually happened (useful for logging, not for correctness).
func (s *Sysctl) EnsureForwarding() (changed bool, err error) {
	cur, err := s.Get("net/ipv4/ip_forward")
	if err != nil {
		return false, err
	}
	if cur == "1" {
		return false, nil
	}
	if err := s.Set("net/ipv4/ip_forward", "1"); err != nil {
		return true, err
	}
	return true, nil
}

func (s *Sysctl) pathFor(param string) string {
	root := s.Root
	if root == "" {
		root = "/proc/sys"
	}
	clean := strings.TrimPrefix(param, "/")
	clean = strings.ReplaceAll(clean, ".", "/")
	return root + "/" + clean
}
