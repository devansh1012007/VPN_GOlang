package wireguard

// fakeClient emulates wgctrl.Client in-memory so unit tests never touch a
// live netlink socket (ADR-002; MASTER_PROMPT constraint #2).
//
// It lives in the _test build so production builds contain zero fakes.

import (
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeClient struct {
	mu      sync.Mutex
	devices map[string]*wgtypes.Device
	closed  bool
}

func newFakeClient(devices ...*wgtypes.Device) *fakeClient {
	m := map[string]*wgtypes.Device{}
	for _, d := range devices {
		dcopy := *d
		m[d.Name] = &dcopy
	}
	return &fakeClient{devices: m}
}

func (f *fakeClient) Device(name string) (*wgtypes.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.devices[name]
	if !ok {
		return nil, errNotFound(name)
	}
	cp := *d
	peers := make([]wgtypes.Peer, len(d.Peers))
	copy(peers, d.Peers)
	cp.Peers = peers
	return &cp, nil
}

func (f *fakeClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.devices[name]
	if !ok {
		return errNotFound(name)
	}
	if cfg.PrivateKey != nil {
		d.PrivateKey = *cfg.PrivateKey
	}
	if cfg.ListenPort != nil {
		d.ListenPort = *cfg.ListenPort
	}
	for _, pc := range cfg.Peers {
		if pc.Remove {
			next := d.Peers[:0]
			for _, p := range d.Peers {
				if p.PublicKey != pc.PublicKey {
					next = append(next, p)
				}
			}
			d.Peers = next
			continue
		}
		// upsert
		replaced := false
		for i := range d.Peers {
			if d.Peers[i].PublicKey == pc.PublicKey {
				d.Peers[i].AllowedIPs = pc.AllowedIPs
				replaced = true
			}
		}
		if !replaced {
			d.Peers = append(d.Peers, wgtypes.Peer{
				PublicKey:  pc.PublicKey,
				AllowedIPs: pc.AllowedIPs,
				Endpoint:   nil,
			})
		}
	}
	return nil
}

func (f *fakeClient) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// errNotFound mirrors wgctrl's error shape for a missing device.
type fakeErr struct{ msg string }

func (e fakeErr) Error() string { return e.msg }

func errNotFound(name string) error {
	return fakeErr{"wgctrl: device not found: " + name}
}

// deviceFixture builds a device with one peer for tests.
func deviceFixture(name string) *wgtypes.Device {
	priv, _ := wgtypes.GeneratePrivateKey()
	pub := priv.PublicKey()
	_, ipnet, _ := net.ParseCIDR("10.100.0.5/32")
	return &wgtypes.Device{
		Name:       name,
		Type:       wgtypes.LinuxKernel,
		PrivateKey: priv,
		PublicKey:  pub,
		ListenPort: 51820,
		Peers: []wgtypes.Peer{{
			PublicKey:         peerKey2(),
			AllowedIPs:        []net.IPNet{*ipnet},
			LastHandshakeTime: time.Unix(0, 0),
			ReceiveBytes:      1024,
			TransmitBytes:     2048,
		}},
	}
}

// peerKey2 makes a second distinct key.
func peerKey2() wgtypes.Key {
	k, _ := wgtypes.GeneratePrivateKey()
	return k.PublicKey()
}
