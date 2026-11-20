package config

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTmpDir returns a fresh temp dir (t.TempDir) — no live network paths touched.
func newTmpDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// validKey crafts a syntactically valid, X25519-clamped 32-byte key in base64
// (shape-compatible with wgtypes.GeneratePrivateKey output).
// Clamping: b[0]&=248, b[31]&=127, b[31]|=64.
func validKey() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	return base64.StdEncoding.EncodeToString(b)
}

func TestDefaultServerValidate(t *testing.T) {
	c := DefaultServer()
	if err := c.Validate(); err != nil {
		t.Fatalf("default server config invalid: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Server)
		wantSub string
	}{
		{"empty iface name", func(c *Server) { c.Interface.Name = "" }, "interface.name"},
		{"long iface name", func(c *Server) { c.Interface.Name = strings.Repeat("w", 16) }, "15 bytes"},
		{"bad listen port", func(c *Server) { c.Interface.ListenPort = 70000 }, "listen_port"},
		{"bad key len", func(c *Server) { c.Interface.PrivateKey = "short" }, "wrong length"},
		{"bad CIDR", func(c *Server) { c.Network.Address = "10.0.0.999/24" }, "network.address"},
		{"too small subnet", func(c *Server) { c.Network.Address = "10.100.0.0/31" }, "prefix <= 30"},
		{"zero offset", func(c *Server) { c.Network.ServerCIDROffset = 0 }, "server_cidr_offset"},
		{"mtu too small", func(c *Server) { c.Network.MTU = 1000 }, "network.mtu"},
		{"no egress when forwarding", func(c *Server) { c.Network.AllowedEgress = nil }, "allowed_egress"},
		{"api no token path", func(c *Server) { c.API.TokenPath = "" }, "api.token_path"},
		{"api bad timeouts", func(c *Server) { c.API.ReadTimeoutSeconds = 0 }, "timeout"},
		{"fw no tag", func(c *Server) { c.Firewall.ChainTag = "" }, "chain_tag"},
		{"empty store path", func(c *Server) { c.Store.Path = "" }, "store.path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultServer()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not name %q", err, tc.wantSub)
			}
		})
	}
}

func TestLoadAndRoundTrip(t *testing.T) {
	dir := newTmpDir(t)
	path := filepath.Join(dir, "server.json")
	c := DefaultServer()
	c.Interface.PrivateKey = validKey()
	c.Store.Path = filepath.Join(dir, "peers.json")
	if err := Save(path, c); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Interface.Name != c.Interface.Name || got.Network.Address != c.Network.Address {
		t.Fatalf("round trip mismatch: %+v vs %+v", got.Interface, c.Interface)
	}
	if got.Interface.PrivateKey != c.Interface.PrivateKey {
		t.Fatalf("round trip lost key material")
	}
	// 0600 mode on the written file.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %o, want 0600", fi.Mode().Perm())
	}
	// No leftover tmp file.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("leftover tmp file present")
	}
}

func TestLoadRejectsTrailingData(t *testing.T) {
	dir := newTmpDir(t)
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte(`{"interface":{"name":"wg0"}} trailing`), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatalf("expected trailing-data error")
	}
}

func TestLoadSyntaxErrorNamesFile(t *testing.T) {
	dir := newTmpDir(t)
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte(`{"interface": {`), 0o600)
	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected syntax error")
	}
	if !strings.Contains(err.Error(), "bad.json") {
		t.Fatalf("error should name file, got: %v", err)
	}
}

// F-001 regression: any safe-print path must redact the private key.
func TestConfigRedactsPrivateKey(t *testing.T) {
	c := DefaultServer()
	c.Interface.PrivateKey = validKey()
	r := c.Redacted()
	if r.Interface.PrivateKey != "REDACTED" {
		t.Fatalf("Redacted() kept %q", r.Interface.PrivateKey)
	}
	if c.Interface.PrivateKey == "REDACTED" {
		t.Fatalf("Redacted() mutated the original")
	}
	// And the redacted view marshals without the key.
	data, _ := json.Marshal(r.Redacted())
	if strings.Contains(string(data), c.Interface.PrivateKey) {
		t.Fatalf("marshaled redacted view contains real key: %s", data)
	}
}

func TestServerIP(t *testing.T) {
	c := DefaultServer() // 10.100.0.0/24, offset 1
	if got := c.ServerIP().String(); got != "10.100.0.1" {
		t.Fatalf("ServerIP = %s, want 10.100.0.1", got)
	}
	c.Network.ServerCIDROffset = 10
	if got := c.ServerIP().String(); got != "10.100.0.10" {
		t.Fatalf("ServerIP = %s, want 10.100.0.10", got)
	}
	c.Network.Address = "not-a-cidr"
	if c.ServerIP() != nil {
		t.Fatalf("ServerIP should be nil for bad CIDR")
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	dir := newTmpDir(t)
	path := filepath.Join(dir, "nope.json")
	c := DefaultServer()
	c.Interface.Name = ""
	if err := Save(path, c); err == nil {
		t.Fatalf("Save must refuse invalid config")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("invalid config must not be written")
	}
}

func TestParseKey(t *testing.T) {
	k := validKey()
	if _, err := ParseKey(k); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := ParseKey("###"); err == nil {
		t.Fatalf("invalid base64 accepted")
	}
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := ParseKey(short); err == nil {
		t.Fatalf("short key accepted")
	}
	// unclamped keys (wrong X25519 form)
	mk := func(mut func([]byte)) string {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(i + 1)
		}
		b[0] &= 248
		b[31] &= 127
		b[31] |= 64
		mut(b)
		return base64.StdEncoding.EncodeToString(b)
	}
	if _, err := ParseKey(mk(func(b []byte) { b[31] |= 0x80 })); err == nil {
		t.Fatalf("bit-7-set key accepted")
	}
	if _, err := ParseKey(mk(func(b []byte) { b[31] &^= 0x40 })); err == nil {
		t.Fatalf("bit-6-clear key accepted")
	}
	if _, err := ParseKey(mk(func(b []byte) { b[0] |= 0x07 })); err == nil {
		t.Fatalf("low-3-bits-set key accepted")
	}
}
