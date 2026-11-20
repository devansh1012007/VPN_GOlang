package network

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestIPAMAllocateSequential(t *testing.T) {
	a, err := NewIPAM("10.100.0.0/24")
	if err != nil {
		t.Fatalf("NewIPAM: %v", err)
	}
	for want := 1; want <= 3; want++ {
		off, ip, err := a.Allocate()
		if err != nil {
			t.Fatalf("allocate #%d: %v", want, err)
		}
		if off != want {
			t.Fatalf("offset = %d, want %d", off, want)
		}
		wantIP := fmt.Sprintf("10.100.0.%d/32", want)
		if ip != wantIP {
			t.Fatalf("ip = %s, want %s", ip, wantIP)
		}
	}
}

func TestIPAMReserveAndRelease(t *testing.T) {
	a, _ := NewIPAM("10.100.0.0/24")
	if _, err := a.Reserve(5); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := a.Reserve(5); err == nil {
		t.Fatalf("double reserve must fail")
	}
	// allocations are lowest-free: 1, 2, 3 (5 stays reserved).
	for _, want := range []int{1, 2, 3} {
		off, _, err := a.Allocate()
		if err != nil || off != want {
			t.Fatalf("allocate = %d, want %d (%v)", off, want, err)
		}
	}
	// release then re-reserve works
	a.Release(5)
	if _, err := a.Reserve(5); err != nil {
		t.Fatalf("reserve after release failed: %v", err)
	}
	// release of never-allocated offset is a no-op
	a.Release(200)
	// out-of-range reserves fail
	if _, err := a.Reserve(0); err == nil {
		t.Fatalf("offset 0 must fail")
	}
	if _, err := a.Reserve(251); err == nil {
		t.Fatalf("offset 251 must fail")
	}
}

func TestIPAMExhaustion(t *testing.T) {
	a, _ := NewIPAM("10.100.0.0/24")
	for i := 0; i < 250; i++ {
		if _, _, err := a.Allocate(); err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
	}
	if _, _, err := a.Allocate(); err == nil {
		t.Fatalf("exhausted subnet must error")
	}
}

func TestIPAMRejections(t *testing.T) {
	bad := []string{
		"10.100.0.0",    // no mask
		"10.100.0.5/24", // not base address
		"2001:db8::/64", // IPv6 unsupported in v1
		"10.100.0.0/31", // prefix > 30
		"garbage",
	}
	for _, cidr := range bad {
		if _, err := NewIPAM(cidr); err == nil {
			t.Fatalf("NewIPAM(%q) must fail", cidr)
		}
	}
}

func TestIPAMOffsetForIP(t *testing.T) {
	a, _ := NewIPAM("10.100.0.0/24")
	off, err := a.OffsetForIP("10.100.0.42")
	if err != nil || off != 42 {
		t.Fatalf("OffsetForIP = %d, %v", off, err)
	}
	if _, err := a.OffsetForIP("10.200.0.1"); err == nil {
		t.Fatalf("outside subnet must fail")
	}
	if _, err := a.OffsetForIP("nope"); err == nil {
		t.Fatalf("invalid IP must fail")
	}
}

func TestIPAMAllocatedSorted(t *testing.T) {
	a, _ := NewIPAM("10.100.0.0/24")
	a.Reserve(9)
	a.Reserve(2)
	a.Reserve(7)
	got := a.Allocated()
	want := []int{2, 7, 9}
	if len(got) != 3 || got[0] != 2 || got[1] != 7 || got[2] != 9 {
		t.Fatalf("Allocated = %v, want %v", got, want)
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"10.0.0.5/32": "10.0.0.5",
		"10.0.0.5":    "10.0.0.5",
	}
	for in, want := range cases {
		if got := NormalizeIP(in); got != want {
			t.Fatalf("NormalizeIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeRunner records iptables calls; emulates a ruleset in memory so
// idempotence is really tested (never execs anything — constraint #2).
type fakeRunner struct {
	mu      sync.Mutex
	present map[string]bool
	calls   []string
	failOn  string // if set, calls containing this substring fail
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{present: map[string]bool{}}
}

func (r *fakeRunner) Run(name string, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	if r.failOn != "" && strings.Contains(line, r.failOn) {
		return fmt.Errorf("simulated iptables failure: %s", line)
	}
	switch {
	case strings.Contains(line, " -C "):
		if r.present[strings.Replace(line, " -C ", " -A ", 1)] {
			return nil
		}
		return fmt.Errorf("rule missing")
	case strings.Contains(line, " -A "):
		r.present[line] = true
		return nil
	case strings.Contains(line, " -D "):
		delete(r.present, strings.Replace(line, " -D ", " -A ", 1))
		return nil
	}
	return nil
}

func (r *fakeRunner) addedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.present {
		if c {
			n++
		}
	}
	return n
}

func specFixture() FirewallSpec {
	return FirewallSpec{
		Interface:    "wg0",
		Subnet:       "10.100.0.0/24",
		EgressIfaces: []string{"eth0"},
		ServerIP:     "10.100.0.1",
		ChainTag:     "VPND",
	}
}

func TestFirewallRenderDeterministic(t *testing.T) {
	fw, err := NewFirewall(specFixture(), newFakeRunner())
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	first := strings.Join(fw.Render(), "\n")
	second := strings.Join(fw.Render(), "\n")
	if first != second {
		t.Fatalf("render not deterministic")
	}
	// must contain the NAT masquerade rule and a tagged DROP
	if !strings.Contains(first, "-j MASQUERADE") {
		t.Fatalf("missing MASQUERADE rule:\n%s", first)
	}
	if !strings.Contains(first, "-j DROP") {
		t.Fatalf("missing DROP rule:\n%s", first)
	}
	if !strings.Contains(first, "--comment VPND") {
		t.Fatalf("rules not tagged for idempotent removal:\n%s", first)
	}
}

func TestFirewallRenderIsInverseOfRemoval(t *testing.T) {
	fw, _ := NewFirewall(specFixture(), newFakeRunner())
	for i, add := range fw.Render() {
		del := fw.RenderRemoval()[i]
		want := strings.Replace(add, " -A ", " -D ", 1)
		if del != want {
			t.Fatalf("removal[%d] = %q, want %q", i, del, want)
		}
	}
}

func TestFirewallApplyIdempotent(t *testing.T) {
	r := newFakeRunner()
	fw, _ := NewFirewall(specFixture(), r)
	if err := fw.Apply(); err != nil {
		t.Fatalf("apply: %v", err)
	}
	n1 := r.addedCount()
	if n1 != len(fw.Render()) {
		t.Fatalf("added %d rules, want %d", n1, len(fw.Render()))
	}
	if err := fw.Apply(); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if n2 := r.addedCount(); n2 != n1 {
		t.Fatalf("second apply added rules (%d → %d); idempotence violated", n1, n2)
	}
}

func TestFirewallRemoveIdempotent(t *testing.T) {
	r := newFakeRunner()
	fw, _ := NewFirewall(specFixture(), r)
	fw.Apply()
	if err := fw.Remove(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if r.addedCount() != 0 {
		t.Fatalf("rules survived removal")
	}
	if err := fw.Remove(); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

func TestFirewallApplyFailurePropagates(t *testing.T) {
	r := newFakeRunner()
	r.failOn = "MASQUERADE"
	fw, _ := NewFirewall(specFixture(), r)
	err := fw.Apply()
	if err == nil {
		t.Fatalf("failure must propagate")
	}
	if !strings.Contains(err.Error(), "MASQUERADE") {
		t.Fatalf("error must name the failing rule: %v", err)
	}
}

func TestFirewallConstructorValidation(t *testing.T) {
	base := specFixture()
	mutations := []struct {
		name   string
		mutate func(*FirewallSpec)
	}{
		{"no iface", func(s *FirewallSpec) { s.Interface = "" }},
		{"bad subnet", func(s *FirewallSpec) { s.Subnet = "bad" }},
		{"no egress", func(s *FirewallSpec) { s.EgressIfaces = nil }},
		{"no tag", func(s *FirewallSpec) { s.ChainTag = "" }},
	}
	for _, tc := range mutations {
		s := base
		tc.mutate(&s)
		if _, err := NewFirewall(s, newFakeRunner()); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
	if _, err := NewFirewall(base, nil); err == nil {
		t.Fatalf("nil runner must be rejected")
	}
}

func TestSysctlTempDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "net", "ipv4")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "ip_forward"), []byte("0\n"), 0o644)

	s := Sysctl{Root: root}
	v, err := s.Get("net/ipv4/ip_forward")
	if err != nil || v != "0" {
		t.Fatalf("get: %q, %v", v, err)
	}
	changed, err := s.EnsureForwarding()
	if err != nil || !changed {
		t.Fatalf("ensure: changed=%v err=%v", changed, err)
	}
	v, _ = s.Get("net/ipv4/ip_forward")
	if v != "1" {
		t.Fatalf("forwarding not enabled: %q", v)
	}
	changed, err = s.EnsureForwarding()
	if err != nil || changed {
		t.Fatalf("second ensure should be a no-op: changed=%v err=%v", changed, err)
	}
}
