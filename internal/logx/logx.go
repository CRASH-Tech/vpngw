// Package logx configures structured JSON logging with masking of
// sensitive attributes.
package logx

import (
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
)

var level = new(slog.LevelVar)

var sensitiveKeys = []string{"password", "passwd", "secret", "token", "refresh", "cookie", "authorization", "nthash", "nt_hash", "master", "private", "key_pem"}

func isSensitive(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// Value patterns that must never reach the logs even inside free text.
var valuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|secret|token)(=|"\s*:\s*"|='|=")([^\s"'&,]+)`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), // JWT
}

var (
	redactMu sync.RWMutex
	redact   = map[string]struct{}{}
)

// AddRedaction registers a literal value (e.g. a configured secret) that
// is replaced with *** wherever it appears in log output.
func AddRedaction(v string) {
	if len(v) < 6 {
		return
	}
	redactMu.Lock()
	redact[v] = struct{}{}
	redactMu.Unlock()
}

// Scrub masks secrets in free-form text.
func Scrub(s string) string {
	for _, re := range valuePatterns {
		if re.NumSubexp() == 3 {
			s = re.ReplaceAllString(s, "$1$2***")
		} else {
			s = re.ReplaceAllString(s, "***")
		}
	}
	redactMu.RLock()
	for v := range redact {
		if strings.Contains(s, v) {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	redactMu.RUnlock()
	return s
}

func replace(_ []string, a slog.Attr) slog.Attr {
	if isSensitive(a.Key) {
		return slog.String(a.Key, "***")
	}
	if a.Value.Kind() == slog.KindString {
		if v := a.Value.String(); v != "" {
			if s := Scrub(v); s != v {
				return slog.String(a.Key, s)
			}
		}
	}
	return a
}

// Setup installs the default JSON logger on w (stdout when nil).
func Setup(w io.Writer, lvl string) {
	if w == nil {
		w = os.Stdout
	}
	SetLevel(lvl)
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: replace})
	slog.SetDefault(slog.New(h))
}

// SetLevel changes the log level at runtime.
func SetLevel(lvl string) {
	switch strings.ToLower(lvl) {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn", "warning":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
}
