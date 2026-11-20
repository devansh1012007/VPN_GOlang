// Package logging provides structured (key=value) logging with levels and a
// pluggable writer. No log line ever receives key material by convention
// (enforced by reviews — see AGENTS.md); this package's job is just format,
// level control, and quiet operation in tests.
package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is the log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// ParseLevel maps a string to Level (accepts debug/info/warn(warning)/error).
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, nil
	case "info", "":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	}
	return LevelInfo, fmt.Errorf("logging: unknown level %q (want debug|info|warn|error)", s)
}

// String returns the canonical level label.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	default:
		return "ERROR"
	}
}

// Logger writes structured lines with level filtering.
type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	min Level
	kv  []any // default fields attached to every line
	now func() time.Time
}

// New builds a Logger writing to w. Nil w means stderr.
func New(w io.Writer, min Level, defaultKV ...any) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{w: w, min: min, kv: defaultKV, now: time.Now}
}

// Debug/Info/Warn/Error log at the obvious levels.
func (l *Logger) Debug(msg string, kv ...any) { l.log(LevelDebug, msg, kv...) }
func (l *Logger) Info(msg string, kv ...any)  { l.log(LevelInfo, msg, kv...) }
func (l *Logger) Warn(msg string, kv ...any)  { l.log(LevelWarn, msg, kv...) }
func (l *Logger) Error(msg string, kv ...any) { l.log(LevelError, msg, kv...) }

func (l *Logger) log(level Level, msg string, kv ...any) {
	if level < l.min {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "time=%s level=%s msg=%q", l.now().UTC().Format(time.RFC3339Nano), level, msg)
	appendKV(&b, l.kv)
	appendKV(&b, kv)
	b.WriteByte('\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprint(l.w, b.String())
}

func appendKV(b *strings.Builder, kv []any) {
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			k = fmt.Sprint(kv[i])
		}
		fmt.Fprintf(b, " %s=%v", sanitizeKey(k), fmt.Sprint(kv[i+1]))
	}
}

func sanitizeKey(k string) string {
	k = strings.Map(func(r rune) rune {
		if r == ' ' || r == '=' || r == '"' {
			return '_'
		}
		return r
	}, k)
	return k
}

// Stderr builds a stderr logger for CLI tools (leveled, timestamped).
func Stderr(min Level) *Logger { return New(os.Stderr, min) }

// Noop returns a logger that writes nowhere (used to silence tests).
func Noop() *Logger { return New(io.Discard, LevelError) }

// Writer exposes the underlying writer for adapters that need it.
func (l *Logger) Writer() io.Writer { return l.w }

// package-level fallback used by cmd binaries before config is loaded.
var std = Stderr(LevelInfo)

// Default returns the package-level logger (stderr, info).
func Default() *Logger { return std }

// SetDefault swaps the package-level logger (main only).
func SetDefault(l *Logger) { std = l }
