// Package network provides IP address management (IPAM), firewall rule
// rendering/application, and kernel parameter handling for the VPN platform.
//
// Nothing in this package mutates state at import or construction time; every
// mutation is an explicit method call (ADR-006), and live mutations are kept
// out of unit tests.
package network

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// IPAM allocates host addresses inside a subnet. Zero value is not usable;
// use NewIPAM.
type IPAM struct {
	subnet net.IPNet
	// used tracks allocated host-part offsets (1..254 for /24).
	used map[int]struct{}
}

// NewIPAM builds an allocator for the given CIDR (IPv4 only, prefix <= 30).
func NewIPAM(cidr string) (*IPAM, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("ipam: invalid CIDR %q: %w", cidr, err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("ipam: only IPv4 subnets supported, got %q", cidr)
	}
	ones, _ := ipnet.Mask.Size()
	if ones > 30 {
		return nil, fmt.Errorf("ipam: prefix /%d too small (want <= /30)", ones)
	}
	if !ip.Equal(ip.Mask(ipnet.Mask)) {
		return nil, fmt.Errorf("ipam: %q is not the network base address", cidr)
	}
	return &IPAM{subnet: *ipnet, used: map[int]struct{}{}}, nil
}

// Reserve marks a specific host offset as used; returns its address with the
// subnet's mask. Fails if out of range or already taken.
func (a *IPAM) Reserve(offset int) (string, error) {
	if err := a.checkOffset(offset); err != nil {
		return "", err
	}
	if _, taken := a.used[offset]; taken {
		return "", fmt.Errorf("ipam: offset %d already allocated", offset)
	}
	a.used[offset] = struct{}{}
	return a.hostIP(offset), nil
}

// Release frees a previously reserved host offset. Releasing an unallocated
// offset is a no-op (idempotent, ADR-006).
func (a *IPAM) Release(offset int) {
	delete(a.used, offset)
}

// Allocate finds the lowest free host offset and reserves it.
// Reserved offsets (network=0, broadcast=last for /24 semantics) and any
// offset already in used are skipped. Returns offset + address.
func (a *IPAM) Allocate() (int, string, error) {
	for offset := 1; offset <= a.MaxHosts(); offset++ {
		if _, taken := a.used[offset]; !taken {
			a.used[offset] = struct{}{}
			return offset, a.hostIP(offset), nil
		}
	}
	return 0, "", fmt.Errorf("ipam: subnet %s exhausted (%d hosts allocated)", a.subnet.String(), len(a.used))
}

// MaxHosts returns the number of allocatable host offsets. The platform
// manages last-octet offsets 1..250 regardless of prefix length (documented
// v1 simplification: a /24 naturally holds them; wider prefixes still cap
// at 250 peers, tracked in EXECUTION_PLAN.md D-4 backlog).
func (a *IPAM) MaxHosts() int {
	return 250
}

// Allocated returns the sorted list of reserved host offsets (for
// reconciliation after restarts).
func (a *IPAM) Allocated() []int {
	out := make([]int, 0, len(a.used))
	for o := range a.used {
		out = append(out, o)
	}
	sort.Ints(out)
	return out
}

// OffsetForIP maps a full address (e.g. "10.100.0.5") back to its host offset,
// or an error if the address is outside the subnet.
func (a *IPAM) OffsetForIP(ipStr string) (int, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("ipam: invalid IP %q", ipStr)
	}
	if !a.subnet.Contains(ip) {
		return 0, fmt.Errorf("ipam: %q outside subnet %s", ipStr, a.subnet.String())
	}
	base := a.subnet.IP.To4()
	v := ip.To4()
	offset := int(v[3]) - int(base[3])
	// Only the last octet varies for /24; wider prefixes (host bits > 8) would
	// need multi-octet math — we deliberately support offsets 1..250 which
	// covers the last-octet space the platform documents.
	if offset < 1 || offset > 250 {
		return 0, fmt.Errorf("ipam: offset %d outside managed range 1..250", offset)
	}
	return offset, nil
}

func (a *IPAM) checkOffset(offset int) error {
	if offset < 1 || offset > 250 {
		return fmt.Errorf("ipam: offset %d outside managed range 1..250", offset)
	}
	return nil
}

// hostIP renders the address for a host offset with /32 suffix (peer routes
// always get /32 on the server side).
func (a *IPAM) hostIP(offset int) string {
	base := a.subnet.IP.To4()
	v := make(net.IP, 4)
	copy(v, base)
	v[3] += byte(offset)
	return fmt.Sprintf("%s/32", v.String())
}

// Subnet returns the managed subnet string.
func (a *IPAM) Subnet() string { return a.subnet.String() }

// String renders a compact debug view (never secret material — subnet + count).
func (a *IPAM) String() string {
	return fmt.Sprintf("IPAM(%s, %d used)", a.subnet.String(), len(a.used))
}

// NormalizeIP strips a CIDR mask if present: "10.0.0.5/32" → "10.0.0.5".
func NormalizeIP(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}
