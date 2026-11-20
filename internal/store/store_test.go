package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devansh1012007/VPN_GOlang/internal/wireguard"
)

func newStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := NewFileStore(filepath.Join(t.TempDir(), "peers.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return s
}

func peerFixture(id, key, addr string) wireguard.Peer {
	return wireguard.Peer{
		ID:        id,
		Name:      "peer-" + id,
		PublicKey: key,
		Address:   addr,
		CreatedAt: time.Unix(1700000000, 0).UTC(),
		UpdatedAt: time.Unix(1700000000, 0).UTC(),
	}
}

func TestAddGetListDelete(t *testing.T) {
	s := newStore(t)
	p1 := peerFixture("a1", "KEYAAAA", "10.100.0.2/32")
	p2 := peerFixture("b2", "KEYBBBB", "10.100.0.3/32")
	if err := s.Add(p1); err != nil {
		t.Fatalf("add1: %v", err)
	}
	if err := s.Add(p2); err != nil {
		t.Fatalf("add2: %v", err)
	}
	got, err := s.Get("a1")
	if err != nil || got.Name != p1.Name {
		t.Fatalf("get: %+v, %v", got, err)
	}
	byKey, err := s.GetByKey("KEYBBBB")
	if err != nil || byKey.ID != "b2" {
		t.Fatalf("getbykey: %+v, %v", byKey, err)
	}
	if _, err := s.Get("zzz"); err != ErrNotFound {
		t.Fatalf("get missing = %v, want ErrNotFound", err)
	}
	list, err := s.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %d peers, %v", len(list), err)
	}
	// List ordering stable by creation time (same) then ID: a1 < b2
	if list[0].ID != "a1" || list[1].ID != "b2" {
		t.Fatalf("list ordering unstable: %v", list)
	}
	rem, err := s.Delete("a1")
	if err != nil || rem.ID != "a1" {
		t.Fatalf("delete: %+v, %v", rem, err)
	}
	if _, err := s.Delete("a1"); err != ErrNotFound {
		t.Fatalf("double delete = %v, want ErrNotFound", err)
	}
}

func TestAddRejectsDuplicates(t *testing.T) {
	s := newStore(t)
	p := peerFixture("a1", "KEYAAAA", "10.100.0.2/32")
	if err := s.Add(p); err != nil {
		t.Fatalf("add: %v", err)
	}
	// duplicate ID
	if err := s.Add(peerFixture("a1", "KEYZZZZ", "10.100.0.9/32")); err == nil {
		t.Fatalf("duplicate ID accepted")
	}
	// duplicate key
	if err := s.Add(peerFixture("x9", "KEYAAAA", "10.100.0.9/32")); err == nil {
		t.Fatalf("duplicate key accepted")
	}
	// duplicate address
	if err := s.Add(peerFixture("y8", "KEYYYYY", "10.100.0.2/32")); err == nil {
		t.Fatalf("duplicate address accepted")
	}
}

func TestPersistenceAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	s1, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("s1: %v", err)
	}
	if err := s1.Add(peerFixture("a1", "KEYAAAA", "10.100.0.2/32")); err != nil {
		t.Fatalf("add: %v", err)
	}
	// "restart": new instance, same path
	s2, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("s2: %v", err)
	}
	got, err := s2.Get("a1")
	if err != nil || got.Address != "10.100.0.2/32" {
		t.Fatalf("peer lost across restart: %+v, %v", got, err)
	}
	addrs, err := s2.AllocatedAddresses()
	if err != nil || len(addrs) != 1 || addrs[0] != "10.100.0.2/32" {
		t.Fatalf("allocated = %v, %v", addrs, err)
	}
}

func TestAtomicWriteLeavesNoTmp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	s, _ := NewFileStore(path)
	if err := s.Add(peerFixture("a1", "KEYAAAA", "10.100.0.2/32")); err != nil {
		t.Fatalf("add: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "peers.json.tmp") {
			t.Fatalf("leftover temp file: %s", e.Name())
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("store mode = %o, want 0600", fi.Mode().Perm())
	}
}

func TestReplaceAll(t *testing.T) {
	s := newStore(t)
	s.Add(peerFixture("a1", "KEYAAAA", "10.100.0.2/32"))
	if err := s.ReplaceAll([]wireguard.Peer{peerFixture("n1", "KEYNNNN", "10.100.0.4/32")}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	list, _ := s.List()
	if len(list) != 1 || list[0].ID != "n1" {
		t.Fatalf("replace-all did not swap the set: %v", list)
	}
}

func TestCorruptStoreFailsLoud(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	os.WriteFile(path, []byte(`{"peers": [broken`), 0o600)
	s, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := s.List(); err == nil {
		t.Fatalf("corrupt store must fail, not silently reset")
	}
}

func TestEmptyStoreStartsClean(t *testing.T) {
	s := newStore(t)
	list, err := s.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("fresh store: %v, %v", list, err)
	}
}

func TestConstructorRejectsEmptyPath(t *testing.T) {
	if _, err := NewFileStore(""); err == nil {
		t.Fatalf("empty path must fail")
	}
}
