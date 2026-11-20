package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devansh1012007/VPN_GOlang/internal/auth"
	"github.com/devansh1012007/VPN_GOlang/internal/store"
	"github.com/devansh1012007/VPN_GOlang/internal/wireguard"
)

// fakeBackend implements Backend in memory; never touches wgctrl or disk.
type fakeBackend struct {
	peers     map[string]wireguard.Peer
	addErr    error
	removeErr error
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{peers: map[string]wireguard.Peer{}}
}

func (f *fakeBackend) AddPeer(name, publicKey string) (*wireguard.Peer, error) {
	if f.addErr != nil {
		return nil, f.addErr
	}
	if _, exists := f.peers[publicKey]; exists {
		return nil, fmt.Errorf("store: public key already registered")
	}
	p := wireguard.Peer{
		ID: "p1", Name: name, PublicKey: publicKey,
		Address:   "10.100.0.2/32",
		CreatedAt: time.Unix(1700000000, 0), UpdatedAt: time.Unix(1700000000, 0),
	}
	f.peers[publicKey] = p
	return &p, nil
}

func (f *fakeBackend) GetPeer(id string) (*wireguard.Peer, error) {
	for _, p := range f.peers {
		if p.ID == id {
			cp := p
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeBackend) ListPeers() ([]wireguard.Peer, error) {
	out := make([]wireguard.Peer, 0, len(f.peers))
	for _, p := range f.peers {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakeBackend) RemovePeer(id string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	for k, p := range f.peers {
		if p.ID == id {
			delete(f.peers, k)
			return nil
		}
	}
	return store.ErrNotFound
}

func (f *fakeBackend) Status() (*StatusReport, error) {
	return &StatusReport{
		Interface: "wg0", ListenPort: 51820, PublicKey: "SRVPUBKEY",
		Subnet: "10.100.0.0/24", PeerCount: len(f.peers),
		Peers: []PeerLive{{
			ID: "p1", Name: "laptop", PublicKey: "PEERPUBKEY",
			Address: "10.100.0.2/32", RxBytes: 10, TxBytes: 20,
		}},
		UptimeSeconds: 42,
	}, nil
}

const testToken = "test-token-0123456789-abcdefghijklmnopqrstuvwxyz"

func newTestServer(t *testing.T, backend Backend) *httptest.Server {
	t.Helper()
	a, err := auth.NewTokenAuthenticator(testToken)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		Addr:          "127.0.0.1:0",
		Authenticator: a,
		Backend:       backend,
		ReadTimeout:   time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.httpd.Handler)
	t.Cleanup(ts.Close)
	return ts
}

func do(t *testing.T, method, url, token string, body any) *http.Response {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return res
}

func TestAuthRequired(t *testing.T) {
	ts := newTestServer(t, newFakeBackend())
	for _, token := range []string{"", "wrong-token-0123456789-abcdefghij"} {
		res := do(t, "GET", ts.URL+"/api/v1/status", token, nil)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("token %q: status = %d, want 401", token, res.StatusCode)
		}
		res.Body.Close()
	}
	// missing header entirely
	res, err := http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no auth header: status = %d, want 401", res.StatusCode)
	}
}

func TestStatusEndpoint(t *testing.T) {
	ts := newTestServer(t, newFakeBackend())
	res := do(t, "GET", ts.URL+"/api/v1/status", testToken, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var rep StatusReport
	if err := json.NewDecoder(res.Body).Decode(&rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Interface != "wg0" || rep.PeerCount != 0 || rep.Subnet != "10.100.0.0/24" {
		t.Fatalf("unexpected report: %+v", rep)
	}
}

func TestAddPeerHappyPath(t *testing.T) {
	ts := newTestServer(t, newFakeBackend())
	res := do(t, "POST", ts.URL+"/api/v1/peers", testToken,
		map[string]string{"name": "laptop", "public_key": "PEERKEYAAA"})
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", res.StatusCode)
	}
	var p wireguard.Peer
	if err := json.NewDecoder(res.Body).Decode(&p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.ID == "" || p.Address == "" {
		t.Fatalf("peer response incomplete: %+v", p)
	}
}

func TestAddPeerValidation(t *testing.T) {
	ts := newTestServer(t, newFakeBackend())
	cases := []struct {
		name string
		body map[string]string
	}{
		{"missing key", map[string]string{"name": "x"}},
		{"missing name", map[string]string{"public_key": "k"}},
	}
	for _, tc := range cases {
		res := do(t, "POST", ts.URL+"/api/v1/peers", testToken, tc.body)
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", tc.name, res.StatusCode)
		}
	}
	// invalid JSON body
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/peers", strings.NewReader("{broken"))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("broken json: status = %d, want 400", res.StatusCode)
	}
}

func TestAddPeerDuplicateConflict(t *testing.T) {
	ts := newTestServer(t, newFakeBackend())
	res := do(t, "POST", ts.URL+"/api/v1/peers", testToken,
		map[string]string{"name": "a", "public_key": "DUPKEY"})
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("first add: %d", res.StatusCode)
	}
	res = do(t, "POST", ts.URL+"/api/v1/peers", testToken,
		map[string]string{"name": "b", "public_key": "DUPKEY"})
	res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate add: status = %d, want 409", res.StatusCode)
	}
}

func TestListAndGetPeer(t *testing.T) {
	fb := newFakeBackend()
	ts := newTestServer(t, fb)
	do(t, "POST", ts.URL+"/api/v1/peers", testToken,
		map[string]string{"name": "laptop", "public_key": "K1"}).Body.Close()
	res := do(t, "GET", ts.URL+"/api/v1/peers", testToken, nil)
	defer res.Body.Close()
	var out struct{ Peers []wireguard.Peer }
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(out.Peers))
	}
	res = do(t, "GET", ts.URL+"/api/v1/peers/p1", testToken, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get peer: status = %d", res.StatusCode)
	}
}

func TestPeerNotFound(t *testing.T) {
	ts := newTestServer(t, newFakeBackend())
	res := do(t, "GET", ts.URL+"/api/v1/peers/nope", testToken, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("get missing: status = %d, want 404", res.StatusCode)
	}
	res = do(t, "DELETE", ts.URL+"/api/v1/peers/nope", testToken, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("delete missing: status = %d, want 404", res.StatusCode)
	}
}

func TestDeletePeer(t *testing.T) {
	fb := newFakeBackend()
	ts := newTestServer(t, fb)
	do(t, "POST", ts.URL+"/api/v1/peers", testToken,
		map[string]string{"name": "laptop", "public_key": "K1"}).Body.Close()
	res := do(t, "DELETE", ts.URL+"/api/v1/peers/p1", testToken, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204", res.StatusCode)
	}
	// gone now
	res = do(t, "GET", ts.URL+"/api/v1/peers/p1", testToken, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("after delete: status = %d, want 404", res.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	ts := newTestServer(t, newFakeBackend())
	res := do(t, "PUT", ts.URL+"/api/v1/peers", testToken, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("put peers: status = %d, want 405", res.StatusCode)
	}
	res = do(t, "POST", ts.URL+"/api/v1/status", testToken, map[string]string{})
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("post status: status = %d, want 405", res.StatusCode)
	}
}

func TestServerConfigValidation(t *testing.T) {
	a, _ := auth.NewTokenAuthenticator(testToken)
	fb := newFakeBackend()
	base := ServerConfig{
		Addr: "127.0.0.1:0", Authenticator: a, Backend: fb,
		ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second,
	}
	bad := []ServerConfig{
		{Addr: "", Authenticator: a, Backend: fb, ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second},
		{Addr: "127.0.0.1:0", Authenticator: nil, Backend: fb, ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second},
		{Addr: "127.0.0.1:0", Authenticator: a, Backend: nil, ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second},
		{Addr: "127.0.0.1:0", Authenticator: a, Backend: fb, ReadTimeout: 0, WriteTimeout: time.Second, IdleTimeout: time.Second},
	}
	for i, cfg := range bad {
		if _, err := NewServer(cfg); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
	if _, err := NewServer(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

// F-002 regression: a device-side failure during removal must NOT delete
// the persisted record.
func TestRemoveFailurePropagates(t *testing.T) {
	fb := newFakeBackend()
	fb.removeErr = fmt.Errorf("wgctrl: device error")
	ts := newTestServer(t, fb)
	do(t, "POST", ts.URL+"/api/v1/peers", testToken,
		map[string]string{"name": "laptop", "public_key": "K1"}).Body.Close()
	res := do(t, "DELETE", ts.URL+"/api/v1/peers/p1", testToken, nil)
	res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("remove failure: status = %d, want 500", res.StatusCode)
	}
	if len(fb.peers) != 1 {
		t.Fatalf("peer was dropped from store despite device failure")
	}
}

func TestBearerTokenParsing(t *testing.T) {
	ts := newTestServer(t, newFakeBackend())
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/status", nil)
	req.Header.Set("Authorization", "bearer "+testToken) // lowercase scheme
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("case-insensitive bearer: status = %d, want 200", res.StatusCode)
	}
	// scheme-less header must fail
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/status", nil)
	req.Header.Set("Authorization", testToken)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do2: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("scheme-less: status = %d, want 401", res.StatusCode)
	}
}
