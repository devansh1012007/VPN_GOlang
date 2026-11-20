package server

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devansh1012007/VPN_GOlang/internal/config"
	"github.com/devansh1012007/VPN_GOlang/internal/logging"
	"github.com/devansh1012007/VPN_GOlang/internal/network"
	"github.com/devansh1012007/VPN_GOlang/internal/store"
	"github.com/devansh1012007/VPN_GOlang/internal/wireguard"
)

// ---- fakes (no live netlink / no iptables exec — constraint #2) ----

type fakeDeviceManager struct {
	deviceConfig  wireguard.DeviceConfig
	status        *wireguard.DeviceStatus
	statusErr     error
	configureErr  error
	removePeerErr error
	removedPeers  []string
}

func (f *fakeDeviceManager) ConfigureDevice(cfg wireguard.DeviceConfig) error {
	if f.configureErr != nil {
		return f.configureErr
	}
	f.deviceConfig = cfg
	return nil
}

func (f *fakeDeviceManager) Status(name string) (*wireguard.DeviceStatus, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return f.status, nil
}

func (f *fakeDeviceManager) RemovePeer(deviceName, publicKey string) error {
	if f.removePeerErr != nil {
		return f.removePeerErr
	}
	f.removedPeers = append(f.removedPeers, publicKey)
	return nil
}

func (f *fakeDeviceManager) Close() error { return nil }

type fakeLinkManager struct {
	ensureCalls []string
	removeCalls []string
	err         error
}

func (f *fakeLinkManager) EnsureLink(name, cidr string, mtu int) error {
	f.ensureCalls = append(f.ensureCalls, name+":"+cidr)
	return f.err
}

func (f *fakeLinkManager) RemoveLink(name string) error {
	f.removeCalls = append(f.removeCalls, name)
	return f.err
}

// fakeIptablesRunner: same emulation as network tests but local (packages
// can't share test helpers).
type fakeIptablesRunner struct {
	added map[string]bool
	err   error
}

func newFakeIptablesRunner() *fakeIptablesRunner {
	return &fakeIptablesRunner{added: map[string]bool{}}
}

func (r *fakeIptablesRunner) Run(name string, args ...string) error {
	line := name + " " + join(args)
	if r.err != nil {
		return r.err
	}
	switch {
	case contains(line, " -C "):
		if r.added[replaceOnce(line, " -C ", " -A ")] {
			return nil
		}
		return errors.New("rule missing")
	case contains(line, " -A "):
		r.added[line] = true
		return nil
	case contains(line, " -D "):
		if r.added[replaceOnce(line, " -D ", " -A ")] {
			delete(r.added, replaceOnce(line, " -D ", " -A "))
			return nil
		}
		return errors.New("rule missing")
	}
	return nil
}

func join(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}

func contains(s, sub string) bool           { return len(s) >= len(sub) && strings.Contains(s, sub) }
func replaceOnce(s, from, to string) string { return strings.Replace(s, from, to, 1) }

// ---- helpers ----

func testConfig(t *testing.T) *config.Server {
	t.Helper()
	c := config.DefaultServer()
	c.Interface.PrivateKey = "" // device fake accepts empty (skipped below)
	c.Store.Path = filepath.Join(t.TempDir(), "peers.json")
	return c
}

// validWireGuardKey generates a real key via wgtypes (the canonical path).
func validWireGuardKey(t *testing.T) string {
	t.Helper()
	k, err := wireguard.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub, err := wireguard.PublicKeyOf(k)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	return pub
}

// newSysctl builds a Sysctl backed by a temp procfs tree with ip_forward=0.
func newSysctl(t *testing.T) *network.Sysctl {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "net", "ipv4")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ip_forward"), []byte("0\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return &network.Sysctl{Root: root}
}

func newServer(t *testing.T, c *config.Server, dev *fakeDeviceManager,
	links *fakeLinkManager, fw *fakeIptablesRunner) (*Server, store.Store) {
	t.Helper()
	st, err := store.NewFileStore(c.Store.Path)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	s, err := New(c, st, Options{
		Logger:   logging.Noop(),
		Devices:  dev,
		Links:    links,
		FwRunner: fw,
		Sysctl:   newSysctl(t),
		Now:      func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, st
}

// ---- tests ----

func TestNewRestoresAllocations(t *testing.T) {
	c := testConfig(t)
	st, _ := store.NewFileStore(c.Store.Path)
	st.Add(wireguard.Peer{
		ID: "p1", Name: "a", PublicKey: "KEY1", Address: "10.100.0.5/32",
		CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0),
	})
	dev, links, fw := &fakeDeviceManager{}, &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	// allocation restored: next Allocate must skip 5
	_, addr, err := s.addForTest()
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if addr != "10.100.0.1/32" {
		t.Fatalf("first allocation = %s, want 10.100.0.1/32", addr)
	}
}

// addForTest is a tiny helper reaching AddPeer without the API layer.
func (s *Server) addForTest() (string, string, error) {
	key, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	pub, _ := wireguard.PublicKeyOf(key)
	p, err := s.AddPeer("t", pub)
	if err != nil {
		return "", "", err
	}
	return p.ID, p.Address, nil
}

func TestAddPeerAllocatesAndPrograms(t *testing.T) {
	c := testConfig(t)
	dev, links, fw := &fakeDeviceManager{}, &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	pub := validWireGuardKey(t)
	p, err := s.AddPeer("laptop", pub)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if p.Address != "10.100.0.1/32" {
		t.Fatalf("address = %s, want first free 10.100.0.1/32", p.Address)
	}
	if len(dev.deviceConfig.Peers) != 1 || dev.deviceConfig.Peers[0].PublicKey != pub {
		t.Fatalf("peer not programmed on device: %+v", dev.deviceConfig.Peers)
	}
	if got := dev.deviceConfig.Peers[0].AllowedIPs; len(got) != 1 || got[0] != "10.100.0.1/32" {
		t.Fatalf("allowed ips = %v", got)
	}
	got, err := s.GetPeer(p.ID)
	if err != nil || got.Name != "laptop" {
		t.Fatalf("GetPeer: %+v %v", got, err)
	}
}

func TestAddPeerValidation(t *testing.T) {
	c := testConfig(t)
	dev, links, fw := &fakeDeviceManager{}, &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	if _, err := s.AddPeer("", "KEY"); err == nil {
		t.Fatalf("empty name accepted")
	}
	if _, err := s.AddPeer("n", "not-a-key"); err == nil {
		t.Fatalf("invalid key accepted")
	}
}

func TestAddPeerDuplicateKeyRejected(t *testing.T) {
	c := testConfig(t)
	dev, links, fw := &fakeDeviceManager{}, &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	pub := validWireGuardKey(t)
	if _, err := s.AddPeer("a", pub); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if _, err := s.AddPeer("b", pub); err == nil {
		t.Fatalf("duplicate accepted")
	}
	// and no address leaked for the failed attempt: next add gets .2
	p, err := s.AddPeer("c", validWireGuardKey(t))
	if err != nil {
		t.Fatalf("third add: %v", err)
	}
	if p.Address != "10.100.0.2/32" {
		t.Fatalf("address = %s, want 10.100.0.2/32", p.Address)
	}
}

// F-002 core: device programming failure rolls the peer fully back.
func TestAddPeerRollsBackOnDeviceFailure(t *testing.T) {
	c := testConfig(t)
	dev := &fakeDeviceManager{configureErr: errors.New("netlink down")}
	links, fw := &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	pub := validWireGuardKey(t)
	if _, err := s.AddPeer("a", pub); err == nil {
		t.Fatalf("add must fail when device programming fails")
	}
	list, _ := s.ListPeers()
	if len(list) != 0 {
		t.Fatalf("store kept peer after device failure: %v", list)
	}
	// address freed: retry (with device healthy) gets .1
	dev.configureErr = nil
	p, err := s.AddPeer("a", pub)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if p.Address != "10.100.0.1/32" {
		t.Fatalf("address not freed after rollback: %s", p.Address)
	}
}

// F-002: removal removes device peer BEFORE store deletion, and a device
// failure preserves the stored record.
func TestRemovePeerOrderAndRollback(t *testing.T) {
	c := testConfig(t)
	dev, links, fw := &fakeDeviceManager{}, &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	pub := validWireGuardKey(t)
	p, _ := s.AddPeer("a", pub)

	// healthy removal
	if err := s.RemovePeer(p.ID); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if len(dev.removedPeers) != 1 || dev.removedPeers[0] != pub {
		t.Fatalf("device peer not removed: %v", dev.removedPeers)
	}
	if _, err := s.GetPeer(p.ID); err != store.ErrNotFound {
		t.Fatalf("stored peer survived: %v", err)
	}

	// device failure path
	p2, _ := s.AddPeer("b", validWireGuardKey(t))
	dev.removePeerErr = errors.New("netlink down")
	if err := s.RemovePeer(p2.ID); err == nil {
		t.Fatalf("RemovePeer must fail when device removal fails")
	}
	if _, err := s.GetPeer(p2.ID); err != nil {
		t.Fatalf("stored peer dropped despite device failure: %v", err)
	}
}

func TestRemovePeerNotFound(t *testing.T) {
	c := testConfig(t)
	dev, links, fw := &fakeDeviceManager{}, &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	if err := s.RemovePeer("ghost"); err != store.ErrNotFound {
		t.Fatalf("remove ghost = %v, want ErrNotFound", err)
	}
}

func TestApplyOrchestratesEverything(t *testing.T) {
	c := testConfig(t)
	// a valid private key so the device config passes validation
	priv, _ := wireguard.GeneratePrivateKey()
	c.Interface.PrivateKey = priv
	dev, links, fw := &fakeDeviceManager{}, &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)

	// seed a stored peer; Apply must program it (reconciliation)
	st, _ := store.NewFileStore(c.Store.Path)
	// (reuse s's store via AddPeer before Apply instead of a second store)
	pub := validWireGuardKey(t)
	p, err := s.AddPeer("a", pub)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	_ = st
	_ = p

	if err := s.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(links.ensureCalls) != 1 || links.ensureCalls[0] != "wg0:10.100.0.1/24" {
		t.Fatalf("EnsureLink calls = %v", links.ensureCalls)
	}
	if len(fw.added) == 0 {
		t.Fatalf("firewall rules not applied")
	}
	if len(dev.deviceConfig.Peers) != 1 {
		t.Fatalf("peers not reconciled onto device")
	}
	if dev.deviceConfig.PrivateKey != priv {
		t.Fatalf("device private key not programmed")
	}
	if dev.deviceConfig.ListenPort != 51820 {
		t.Fatalf("listen port = %d", dev.deviceConfig.ListenPort)
	}
}

func TestApplyIdempotent(t *testing.T) {
	c := testConfig(t)
	priv, _ := wireguard.GeneratePrivateKey()
	c.Interface.PrivateKey = priv
	dev, links, fw := &fakeDeviceManager{}, &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	for i := 0; i < 3; i++ {
		if err := s.Apply(); err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
	}
	if len(links.ensureCalls) != 3 {
		// link ensure is called per Apply — that is fine (idempotent at
		// LinkManager level); we assert the count to document it.
		t.Fatalf("ensure calls = %d, want 3", len(links.ensureCalls))
	}
}

func TestTearDownRemovesFirewallOnlyByDefault(t *testing.T) {
	c := testConfig(t)
	dev, links, fw := &fakeDeviceManager{}, &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	s.Apply()
	if err := s.TearDown(); err != nil {
		t.Fatalf("TearDown: %v", err)
	}
	if len(fw.added) != 0 {
		t.Fatalf("firewall rules survived teardown")
	}
	if len(links.removeCalls) != 0 {
		t.Fatalf("link removed although remove_interface_on_stop=false: %v", links.removeCalls)
	}
	// with the flag on, the link goes away too
	c.RemoveIfaceOnStop = true
	s2, _ := newServer(t, c, dev, links, fw)
	s2.Apply()
	if err := s2.TearDown(); err != nil {
		t.Fatalf("TearDown2: %v", err)
	}
	if len(links.removeCalls) != 1 {
		t.Fatalf("link not removed: %v", links.removeCalls)
	}
}

func TestStatusMergesStoreAndDevice(t *testing.T) {
	c := testConfig(t)
	dev := &fakeDeviceManager{
		status: &wireguard.DeviceStatus{
			Name: "wg0", ListenPort: 51820, PublicKey: "SRVPUB",
			Peers: []wireguard.PeerStatus{{
				PublicKey: "PEERPUB", Endpoint: "1.2.3.4:5",
				AllowedIPs:      []string{"10.100.0.1/32"},
				LastHandshake:   time.Unix(1699990000, 0),
				TransferRxBytes: 100, TransferTxBytes: 200,
			}},
		},
	}
	links, fw := &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	// store a peer with the same public key
	st, _ := store.NewFileStore(c.Store.Path)
	st.Add(wireguard.Peer{ID: "px", Name: "laptop", PublicKey: "PEERPUB",
		Address: "10.100.0.1/32", CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0)})
	s2, err := New(c, st, Options{
		Logger: logging.Noop(), Devices: dev, Links: links, FwRunner: fw,
		Sysctl: newSysctl(t),
		Now:    func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s = s2
	rep, err := s.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if rep.Interface != "wg0" || rep.Subnet != "10.100.0.0/24" || rep.PeerCount != 1 {
		t.Fatalf("report header: %+v", rep)
	}
	if len(rep.Peers) != 1 {
		t.Fatalf("peers = %d", len(rep.Peers))
	}
	p := rep.Peers[0]
	if p.ID != "px" || p.Name != "laptop" || p.Endpoint != "1.2.3.4:5" || p.RxBytes != 100 || p.TxBytes != 200 {
		t.Fatalf("peer merge wrong: %+v", p)
	}
	if rep.UptimeSeconds != 0 {
		t.Fatalf("uptime = %d, want 0 for fixed clock", rep.UptimeSeconds)
	}
}

func TestStatusFallsBackToStoreWhenDeviceDown(t *testing.T) {
	c := testConfig(t)
	dev := &fakeDeviceManager{statusErr: errors.New("no such device")}
	links, fw := &fakeLinkManager{}, newFakeIptablesRunner()
	s, _ := newServer(t, c, dev, links, fw)
	p, _ := s.AddPeer("a", validWireGuardKey(t))
	rep, err := s.Status()
	if err != nil {
		t.Fatalf("Status with device down: %v", err)
	}
	if rep.PeerCount != 1 || len(rep.Peers) != 1 || rep.Peers[0].ID != p.ID {
		t.Fatalf("store fallback wrong: %+v", rep)
	}
}

func TestNewRejectsBadCollaborators(t *testing.T) {
	c := testConfig(t)
	st, _ := store.NewFileStore(c.Store.Path)
	base := Options{
		Devices:  &fakeDeviceManager{},
		Links:    &fakeLinkManager{},
		FwRunner: newFakeIptablesRunner(),
		Sysctl:   &network.Sysctl{},
	}
	cases := []func(o *Options){
		func(o *Options) { o.Devices = nil },
		func(o *Options) { o.Links = nil },
		func(o *Options) { o.FwRunner = nil },
		func(o *Options) { o.Sysctl = nil },
	}
	for i, mutate := range cases {
		o := base
		mutate(&o)
		if _, err := New(c, st, o); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
	if _, err := New(nil, st, base); err == nil {
		t.Fatalf("nil config must fail")
	}
	if _, err := New(c, nil, base); err == nil {
		t.Fatalf("nil store must fail")
	}
}

func TestNewRejectsOutOfSubnetStoredAddress(t *testing.T) {
	c := testConfig(t)
	st, _ := store.NewFileStore(c.Store.Path)
	st.Add(wireguard.Peer{ID: "p1", PublicKey: "K", Address: "10.200.0.9/32",
		CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0)})
	dev, links, fw := &fakeDeviceManager{}, &fakeLinkManager{}, newFakeIptablesRunner()
	if _, err := newServerErr(t, c, dev, links, fw); err == nil {
		t.Fatalf("out-of-subnet stored address must fail construction")
	}
}

func newServerErr(t *testing.T, c *config.Server, dev *fakeDeviceManager,
	links *fakeLinkManager, fw *fakeIptablesRunner) (*Server, error) {
	t.Helper()
	st, err := store.NewFileStore(c.Store.Path)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return New(c, st, Options{
		Logger: logging.Noop(), Devices: dev, Links: links, FwRunner: fw,
		Sysctl: newSysctl(t),
	})
}
