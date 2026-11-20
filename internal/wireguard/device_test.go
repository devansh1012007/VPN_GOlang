package wireguard

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestConfigureDeviceFullReconcile(t *testing.T) {
	dev := deviceFixture("wg0")
	m := NewManagerWithClient(newFakeClient(dev))

	priv, _ := wgtypes.GeneratePrivateKey()
	peerA := priv.PublicKey().String()

	priv2, _ := wgtypes.GeneratePrivateKey()
	peerB := priv2.PublicKey().String()

	// The fixture device already has one peer. Desired set: A and B. Desired set: A and B
	// (so pub2's peer must be removed, A and B added).
	err := m.ConfigureDevice(DeviceConfig{
		Name:       "wg0",
		PrivateKey: priv.String(),
		ListenPort: 51821,
		Peers: []PeerConfig{
			{PublicKey: peerA, AllowedIPs: []string{"10.100.0.2/32"}},
			{PublicKey: peerB, AllowedIPs: []string{"10.100.0.3/32"}},
		},
	})
	if err != nil {
		t.Fatalf("ConfigureDevice: %v", err)
	}

	st, err := m.Status("wg0")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.ListenPort != 51821 {
		t.Fatalf("listen port = %d, want 51821", st.ListenPort)
	}
	if len(st.Peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(st.Peers))
	}
	for _, p := range st.Peers {
		if p.PublicKey != peerA && p.PublicKey != peerB {
			t.Fatalf("unexpected peer %q present", KeyFingerprint(p.PublicKey))
		}
	}
}

func TestConfigureDeviceIsIdempotent(t *testing.T) {
	dev := deviceFixture("wg0")
	m := NewManagerWithClient(newFakeClient(dev))
	priv, _ := wgtypes.GeneratePrivateKey()
	cfg := DeviceConfig{
		Name:       "wg0",
		PrivateKey: priv.String(),
		ListenPort: 51820,
		Peers:      []PeerConfig{{PublicKey: priv.PublicKey().String(), AllowedIPs: []string{"10.100.0.7/32"}}},
	}
	if err := m.ConfigureDevice(cfg); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := m.ConfigureDevice(cfg); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	st, _ := m.Status("wg0")
	if len(st.Peers) != 1 {
		t.Fatalf("peers = %d, want 1 (idempotence violated)", len(st.Peers))
	}
}

func TestConfigureDeviceRejectsBadKeys(t *testing.T) {
	m := NewManagerWithClient(newFakeClient(deviceFixture("wg0")))
	if err := m.ConfigureDevice(DeviceConfig{Name: "wg0", PrivateKey: "!!!", ListenPort: 1}); err == nil {
		t.Fatalf("expected error for invalid private key")
	}
}

func TestConfigureDeviceRejectsBadCIDR(t *testing.T) {
	m := NewManagerWithClient(newFakeClient(deviceFixture("wg0")))
	priv, _ := wgtypes.GeneratePrivateKey()
	err := m.ConfigureDevice(DeviceConfig{
		Name:       "wg0",
		PrivateKey: priv.String(),
		Peers:      []PeerConfig{{PublicKey: priv.PublicKey().String(), AllowedIPs: []string{"300.0.0.1/32"}}},
	})
	if err == nil {
		t.Fatalf("expected error for invalid allowed IP")
	}
}

func TestRemovePeer(t *testing.T) {
	dev := deviceFixture("wg0")
	m := NewManagerWithClient(newFakeClient(dev))
	priv, _ := wgtypes.GeneratePrivateKey()
	pk := priv.PublicKey().String()
	if err := m.ConfigureDevice(DeviceConfig{
		Name:       "wg0",
		PrivateKey: priv.String(),
		Peers:      []PeerConfig{{PublicKey: pk, AllowedIPs: []string{"10.100.0.9/32"}}},
	}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	if err := m.RemovePeer("wg0", pk); err != nil {
		t.Fatalf("remove: %v", err)
	}
	st, _ := m.Status("wg0")
	if len(st.Peers) != 0 {
		t.Fatalf("peer survived removal")
	}
}

func TestStatusUnknownDevice(t *testing.T) {
	m := NewManagerWithClient(newFakeClient(deviceFixture("wg0")))
	if _, err := m.Status("nope0"); err == nil {
		t.Fatalf("expected error for unknown device")
	}
}

func TestStatusMapsFields(t *testing.T) {
	dev := deviceFixture("wg0")
	dev.Peers[0].Endpoint = nil
	dev.Peers[0].ReceiveBytes = 111
	dev.Peers[0].TransmitBytes = 222
	dev.Peers[0].LastHandshakeTime = time.Unix(1700000000, 0)
	m := NewManagerWithClient(newFakeClient(dev))
	st, err := m.Status("wg0")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Peers[0].TransferRxBytes != 111 || st.Peers[0].TransferTxBytes != 222 {
		t.Fatalf("transfer counters not mapped")
	}
	if !st.Peers[0].LastHandshake.Equal(time.Unix(1700000000, 0)) {
		t.Fatalf("handshake not mapped")
	}
	if len(st.Peers[0].AllowedIPs) != 1 || st.Peers[0].AllowedIPs[0] != "10.100.0.5/32" {
		t.Fatalf("allowed ips not mapped: %v", st.Peers[0].AllowedIPs)
	}
}

func TestKeyRoundTrip(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(priv) != 44 {
		t.Fatalf("generated key length = %d, want 44", len(priv))
	}
	pub, err := PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("derive public: %v", err)
	}
	if pub == priv {
		t.Fatalf("public key must differ from private key")
	}
	if _, err := ParseKey("not-a-key"); err == nil {
		t.Fatalf("ParseKey must reject garbage")
	}
}

func TestPeerAllowedIPs(t *testing.T) {
	p := &Peer{Address: "10.100.0.5/32"}
	if got := p.AllowedIPs(); len(got) != 1 || got[0] != "10.100.0.5/32" {
		t.Fatalf("AllowedIPs = %v", got)
	}
	empty := &Peer{}
	if empty.AllowedIPs() != nil {
		t.Fatalf("AllowedIPs on empty address must be nil")
	}
}

func TestKeyFingerprintNeverLeaksKey(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	fp := KeyFingerprint(k.PublicKey().String())
	if len(fp) != 8 || fp == k.PublicKey().String() {
		t.Fatalf("fingerprint %q not a safe prefix", fp)
	}
	if KeyFingerprint("short") != "<invalid>" {
		t.Fatalf("short key should map to <invalid>")
	}
}
