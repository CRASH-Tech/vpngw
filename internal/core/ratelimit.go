package core

import (
	"sync"
	"time"
)

// Limiter blocks keys (logins, IPs) after too many failures in a window.
type Limiter struct {
	mu       sync.Mutex
	limit    func() int
	window   func() time.Duration
	block    func() time.Duration
	failures map[string][]time.Time
	blocked  map[string]time.Time
}

// NewLimiter creates a limiter with dynamic settings.
func NewLimiter(limit func() int, window, block func() time.Duration) *Limiter {
	return &Limiter{limit: limit, window: window, block: block, failures: map[string][]time.Time{}, blocked: map[string]time.Time{}}
}

// Blocked reports whether key is blocked and until when.
func (l *Limiter) Blocked(key string) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.blocked[key]
	if !ok {
		return false, time.Time{}
	}
	if time.Now().After(until) {
		delete(l.blocked, key)
		return false, time.Time{}
	}
	return true, until
}

// Fail records a failure; it returns true when the key just got blocked.
func (l *Limiter) Fail(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window())
	f := l.failures[key][:0]
	for _, t := range l.failures[key] {
		if t.After(cutoff) {
			f = append(f, t)
		}
	}
	f = append(f, now)
	l.failures[key] = f
	if len(f) >= l.limit() {
		l.blocked[key] = now.Add(l.block())
		delete(l.failures, key)
		return true
	}
	return false
}

// Success clears failures of key.
func (l *Limiter) Success(key string) {
	l.mu.Lock()
	delete(l.failures, key)
	l.mu.Unlock()
}

// Unblock removes a block (admin action).
func (l *Limiter) Unblock(key string) {
	l.mu.Lock()
	delete(l.blocked, key)
	delete(l.failures, key)
	l.mu.Unlock()
}

// BlockedKeys lists active blocks.
func (l *Limiter) BlockedKeys() map[string]time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]time.Time{}
	now := time.Now()
	for k, v := range l.blocked {
		if now.Before(v) {
			out[k] = v
		}
	}
	return out
}

// GC drops stale entries.
func (l *Limiter) GC() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-l.window())
	for k, f := range l.failures {
		if len(f) == 0 || f[len(f)-1].Before(cutoff) {
			delete(l.failures, k)
		}
	}
	for k, v := range l.blocked {
		if now.After(v) {
			delete(l.blocked, k)
		}
	}
}
