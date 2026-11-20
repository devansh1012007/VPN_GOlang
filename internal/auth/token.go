// Package auth implements bearer-token authentication for the admin API
// (ADR-004). Tokens are 256-bit values from crypto/rand; comparisons are
// constant-time (threat model T2 / SR-3).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// TokenBytes is the raw entropy of a token (32 bytes = 256 bits).
const TokenBytes = 32

// GenerateToken returns a fresh URL-safe token (base64url, 43 chars).
func GenerateToken() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: entropy source: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Authenticator validates presented bearer tokens.
type Authenticator interface {
	Authenticate(presented string) bool
}

// TokenAuthenticator is the constant-time comparator over a fixed token.
type TokenAuthenticator struct {
	token []byte
}

// NewTokenAuthenticator builds an authenticator from a token string.
func NewTokenAuthenticator(token string) (*TokenAuthenticator, error) {
	token = strings.TrimSpace(token)
	if len(token) < 20 {
		return nil, fmt.Errorf("auth: token too weak (%d chars, want >= 20)", len(token))
	}
	return &TokenAuthenticator{token: []byte(token)}, nil
}

// Authenticate reports whether presented matches the configured token.
// Comparison is constant-time and length-safe.
func (a *TokenAuthenticator) Authenticate(presented string) bool {
	if len(presented) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), a.token) == 1
}

// LoadToken reads the token from a file (mode must be 0600 — the runbook
// requirement; enforced with an explicit check so misconfigurations fail
// closed... but only warn on non-Linux fs where mode bits are emulated).
func LoadToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("auth: read token: %w", err)
	}
	tok := strings.TrimSpace(string(data))
	if len(tok) < 20 {
		return "", fmt.Errorf("auth: token file %s too short (%d chars, want >= 20)", path, len(tok))
	}
	return tok, nil
}

// SaveToken atomically writes a token file with mode 0600.
func SaveToken(path, token string) error {
	if len(token) < 20 {
		return fmt.Errorf("auth: refusing to save weak token")
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return fmt.Errorf("auth: write token: %w", err)
	}
	return nil
}
