// Package store persists peer records (ADR-005): a single JSON document with
// atomic writes (temp file + rename), mode 0600, public keys only.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/devansh1012007/VPN_GOlang/internal/wireguard"
)

// Store is the peer persistence interface (narrow by design so a SQLite
// driver can replace the file backend later — ADR-005).
type Store interface {
	Add(p wireguard.Peer) error
	Get(id string) (*wireguard.Peer, error)
	GetByKey(publicKey string) (*wireguard.Peer, error)
	List() ([]wireguard.Peer, error)
	Delete(id string) (*wireguard.Peer, error)
	// AllocatedAddresses returns every persisted peer address (for IPAM
	// reconciliation after restarts).
	AllocatedAddresses() ([]string, error)
	// ReplaceAll atomically swaps the full peer set (used by reconciliation).
	ReplaceAll(peers []wireguard.Peer) error
}

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = fmt.Errorf("store: peer not found")

// FileStore is the JSON-file Store implementation.
type FileStore struct {
	mu   sync.Mutex
	path string
}

// persistedDoc is the on-disk document.
type persistedDoc struct {
	Version int              `json:"version"`
	Peers   []wireguard.Peer `json:"peers"`
}

// NewFileStore opens (or lazily creates) the store at path. No network or
// privileged access happens here.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, fmt.Errorf("store: path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("store: create dir: %w", err)
	}
	return &FileStore{path: path}, nil
}

// Path returns the store file location.
func (s *FileStore) Path() string { return s.path }

func (s *FileStore) load() (persistedDoc, error) {
	doc := persistedDoc{Version: 1}
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return doc, nil // fresh store
	}
	if err != nil {
		return doc, fmt.Errorf("store: read %s: %w", s.path, err)
	}
	if len(data) == 0 {
		return doc, nil
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("store: parse %s: %w", s.path, err)
	}
	return doc, nil
}

// save writes atomically: temp in the same directory, fsync, rename.
func (s *FileStore) save(doc persistedDoc) error {
	sortPeers(doc.Peers)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("store: temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("store: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("store: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("store: close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("store: chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// Add inserts a new peer; duplicate IDs and duplicate public keys or
// addresses are rejected.
func (s *FileStore) Add(p wireguard.Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return err
	}
	for _, e := range doc.Peers {
		if e.ID == p.ID {
			return fmt.Errorf("store: peer id %q already exists", p.ID)
		}
		if e.PublicKey == p.PublicKey {
			return fmt.Errorf("store: public key already registered")
		}
		if e.Address == p.Address {
			return fmt.Errorf("store: address %s already allocated", p.Address)
		}
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = p.CreatedAt
	}
	doc.Peers = append(doc.Peers, p)
	return s.save(doc)
}

// Get returns a peer by ID.
func (s *FileStore) Get(id string) (*wireguard.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	for _, e := range doc.Peers {
		if e.ID == id {
			cp := e
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// GetByKey returns a peer by public key.
func (s *FileStore) GetByKey(publicKey string) (*wireguard.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	for _, e := range doc.Peers {
		if e.PublicKey == publicKey {
			cp := e
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// List returns all peers sorted by creation time (stable ordering).
func (s *FileStore) List() ([]wireguard.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	sortPeers(doc.Peers)
	return doc.Peers, nil
}

// Delete removes a peer by ID and returns the removed record.
func (s *FileStore) Delete(id string) (*wireguard.Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	for i, e := range doc.Peers {
		if e.ID == id {
			doc.Peers = append(doc.Peers[:i], doc.Peers[i+1:]...)
			if err := s.save(doc); err != nil {
				return nil, err
			}
			cp := e
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

// AllocatedAddresses returns every peer address.
func (s *FileStore) AllocatedAddresses() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Peers))
	for _, p := range doc.Peers {
		out = append(out, p.Address)
	}
	return out, nil
}

// ReplaceAll atomically swaps the full peer set.
func (s *FileStore) ReplaceAll(peers []wireguard.Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(persistedDoc{Version: 1, Peers: peers})
}

func sortPeers(peers []wireguard.Peer) {
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].CreatedAt.Equal(peers[j].CreatedAt) {
			return peers[i].ID < peers[j].ID
		}
		return peers[i].CreatedAt.Before(peers[j].CreatedAt)
	})
}
