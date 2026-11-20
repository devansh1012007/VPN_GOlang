package network

import (
	"fmt"
	"net"
	"strings"
)

// FirewallSpec is the desired ruleset for one VPN subnet (pure data; safe to
// print — contains no secrets).
type FirewallSpec struct {
	// Interface is the wg link name (e.g. "wg0").
	Interface string
	// Subnet is the VPN CIDR (e.g. "10.100.0.0/24").
	Subnet string
	// EgressIfaces are host interfaces VPN traffic may NAT out of.
	EgressIfaces []string
	// ServerIP is the VPN address of the server (no CIDR suffix).
	ServerIP string
	// ChainTag prefixes rule comments for idempotent removal.
	ChainTag string
}

// Firewall renders iptables rules and applies/removes them idempotently
// (ADR-006). Apply/Remove are the ONLY methods that mutate the host; Render
// is pure and used by --dry-run and by unit tests.
type Firewall struct {
	spec FirewallSpec
	// runner executes commands; abstracted so tests never exec iptables.
	runner CommandRunner
}

// CommandRunner executes one command with args (no shell — ADR-006 forbids
// shelling out with PATH-influenced strings).
type CommandRunner interface {
	Run(name string, args ...string) error
}

// NewFirewall builds a Firewall; no host mutation happens here.
func NewFirewall(spec FirewallSpec, runner CommandRunner) (*Firewall, error) {
	if spec.Interface == "" {
		return nil, fmt.Errorf("firewall: interface required")
	}
	if _, _, err := net.ParseCIDR(spec.Subnet); err != nil {
		return nil, fmt.Errorf("firewall: subnet %q invalid: %w", spec.Subnet, err)
	}
	if len(spec.EgressIfaces) == 0 {
		return nil, fmt.Errorf("firewall: at least one egress interface required")
	}
	if spec.ChainTag == "" {
		return nil, fmt.Errorf("firewall: chain tag required")
	}
	if runner == nil {
		return nil, fmt.Errorf("firewall: command runner required")
	}
	return &Firewall{spec: spec, runner: runner}, nil
}

// Render produces the full ruleset as iptables(8) statements, one per line.
// Ordering is stable so --dry-run output is diffable and testable.
//
// Semantics (threat model T8):
//   - VPN subnet → anywhere, but only via NAT on the listed egress interfaces;
//   - FORWARD allowed for traffic whose *both* endpoints stay inside the VPN subnet;
//   - NAT (masquerade) so peers reach the internet with the server's address;
//   - every rule carries a comment tagged with ChainTag for idempotent removal.
func (f *Firewall) Render() []string {
	subnet := f.spec.Subnet
	iface := f.spec.Interface
	tag := f.spec.ChainTag
	rules := []string{
		fmt.Sprintf("iptables -t filter -A FORWARD -i %s -o %s -m comment --comment %s -j ACCEPT", iface, iface, tag),
		fmt.Sprintf("iptables -t filter -A FORWARD -i %s ! -o %s -m comment --comment %s -j DROP", iface, iface, tag),
		fmt.Sprintf("iptables -t filter -A FORWARD -d %s -o %s -m comment --comment %s -j ACCEPT", subnet, iface, tag),
	}
	for _, eg := range f.spec.EgressIfaces {
		rules = append(rules,
			fmt.Sprintf("iptables -t filter -A FORWARD -i %s -o %s -m comment --comment %s -j ACCEPT", iface, eg, tag),
			fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -m comment --comment %s -j MASQUERADE", subnet, eg, tag),
		)
	}
	return rules
}

// RenderRemoval produces the exact inverse statements for Render's rules.
func (f *Firewall) RenderRemoval() []string {
	out := make([]string, 0, 8)
	for _, r := range f.Render() {
		out = append(out, strings.Replace(r, " -A ", " -D ", 1))
	}
	return out
}

// Apply installs the rendered ruleset idempotently: for every rule it first
// checks existence (-C) and only appends (-A) when missing, so re-running
// Apply never duplicates rules (ADR-006).
func (f *Firewall) Apply() error {
	for _, r := range f.Render() {
		args := strings.Fields(r)[1:] // drop leading "iptables"
		check := swapAction(args, "-A", "-C")
		if err := f.runner.Run("iptables", check...); err == nil {
			continue // rule already present
		}
		if err := f.runner.Run("iptables", args...); err != nil {
			return fmt.Errorf("firewall apply: %w (rule: %s)", err, r)
		}
	}
	return nil
}

// Remove deletes exactly the rules Apply created, idempotently: rules that
// are already absent are skipped (check-first).
func (f *Firewall) Remove() error {
	for _, r := range f.RenderRemoval() {
		args := strings.Fields(r)[1:]
		// args are the -D form; verify presence with -C before deleting.
		present := swapAction(args, "-D", "-C")
		if err := f.runner.Run("iptables", present...); err != nil {
			continue // not present → nothing to remove
		}
		if err := f.runner.Run("iptables", args...); err != nil {
			return fmt.Errorf("firewall remove: %w (rule: %s)", err, r)
		}
	}
	return nil
}

// swapAction replaces the first occurrence of from with to in args.
func swapAction(args []string, from, to string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i, a := range out {
		if a == from {
			out[i] = to
			break
		}
	}
	return out
}

// Spec returns the spec (safe to log: contains no secrets).
func (f *Firewall) Spec() FirewallSpec { return f.spec }
