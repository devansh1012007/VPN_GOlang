package logging

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func newBufLogger(t *testing.T, min Level) (*Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	l := New(&buf, min)
	l.now = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	return l, &buf
}

func TestLevelFiltering(t *testing.T) {
	l, buf := newBufLogger(t, LevelWarn)
	l.Debug("d")
	l.Info("i")
	l.Warn("w")
	l.Error("e")
	out := buf.String()
	if strings.Contains(out, "d") || strings.Contains(out, "msg=\"i\"") {
		t.Fatalf("below-min levels leaked:\n%s", out)
	}
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "level=ERROR") {
		t.Fatalf("warn/error missing:\n%s", out)
	}
}

func TestStructuredFields(t *testing.T) {
	l, buf := newBufLogger(t, LevelInfo)
	l.Info("peer added", "peer_id", "a1", "address", "10.100.0.2/32")
	out := buf.String()
	for _, want := range []string{`msg="peer added"`, "peer_id=a1", "address=10.100.0.2/32"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.HasPrefix(out, "time=") {
		t.Fatalf("missing timestamp prefix:\n%s", out)
	}
}

func TestDefaultKVAttached(t *testing.T) {
	l, buf := newBufLogger(t, LevelInfo)
	l.kv = []any{"component", "vpnd"}
	l.Info("hello")
	if !strings.Contains(buf.String(), "component=vpnd") {
		t.Fatalf("default kv missing:\n%s", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]Level{
		"debug": LevelDebug, "INFO": LevelInfo, "": LevelInfo,
		"warn": LevelWarn, "warning": LevelWarn, "error": LevelError,
	}
	for in, want := range cases {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Fatalf("ParseLevel(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Fatalf("unknown level must error")
	}
}

func TestKeySanitization(t *testing.T) {
	l, buf := newBufLogger(t, LevelInfo)
	l.Info("m", "weird key=with=chars", "v")
	out := buf.String()
	if strings.Contains(out, "weird key=with=chars=") {
		t.Fatalf("unsafe key leaked into line:\n%s", out)
	}
	if !strings.Contains(out, "weird_key_with_chars=v") {
		t.Fatalf("sanitized key missing:\n%s", out)
	}
}

func TestNoopWritesNothing(t *testing.T) {
	l := Noop()
	l.Error("boom")
	if l.Writer() == nil {
		t.Fatalf("writer must not be nil")
	}
}
