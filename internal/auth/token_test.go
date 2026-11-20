package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateTokenStrength(t *testing.T) {
	t1, err := GenerateToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(t1) != 43 { // base64url of 32 bytes without padding
		t.Fatalf("token length = %d, want 43", len(t1))
	}
	t2, _ := GenerateToken()
	if t1 == t2 {
		t.Fatalf("tokens must be unique")
	}
}

func TestAuthenticate(t *testing.T) {
	tok, _ := GenerateToken()
	a, err := NewTokenAuthenticator(tok)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	if !a.Authenticate(tok) {
		t.Fatalf("correct token rejected")
	}
	if a.Authenticate("wrong-token-wrong-token-wrong") {
		t.Fatalf("wrong token accepted")
	}
	if a.Authenticate("") {
		t.Fatalf("empty token accepted")
	}
	if a.Authenticate(tok[:len(tok)-1]) {
		t.Fatalf("truncated token accepted")
	}
}

func TestWeakTokenRejected(t *testing.T) {
	if _, err := NewTokenAuthenticator("short"); err == nil {
		t.Fatalf("weak token must be rejected")
	}
	if _, err := NewTokenAuthenticator(""); err == nil {
		t.Fatalf("empty token must be rejected")
	}
}

func TestTokenFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	tok, _ := GenerateToken()
	if err := SaveToken(path, tok); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadToken(path)
	if err != nil || got != tok {
		t.Fatalf("load: %q, %v", got, err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("token mode = %o, want 0600", fi.Mode().Perm())
	}
}

func TestLoadTokenFailures(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte("tooshort"), 0o600)
	if _, err := LoadToken(short); err == nil {
		t.Fatalf("short token file must fail")
	}
	if _, err := LoadToken(filepath.Join(dir, "missing")); err == nil {
		t.Fatalf("missing file must fail")
	}
	if err := SaveToken(short, "weak"); err == nil {
		t.Fatalf("saving weak token must fail")
	}
}

// Whitespace is trimmed, so a trailing newline from a file is fine.
func TestTokenTrimming(t *testing.T) {
	a, err := NewTokenAuthenticator("  abcdefghijklmnopqrstuvwxyz  ")
	if err != nil {
		t.Fatalf("trim: %v", err)
	}
	if !a.Authenticate("abcdefghijklmnopqrstuvwxyz") {
		t.Fatalf("token with surrounding whitespace rejected")
	}
}
