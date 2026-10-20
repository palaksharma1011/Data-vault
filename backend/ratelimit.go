package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// FailureLimiter tracks failed attempts per key (username or IP) and
// locks the key out after too many failures. Repeat offenders get longer
// lockouts (doubling, capped at maxLock).
type FailureLimiter struct {
	mu      sync.Mutex
	max     int           // failures allowed inside window
	window  time.Duration // sliding window for counting failures
	baseLck time.Duration // first lockout length
	maxLock time.Duration
	now     func() time.Time
	m       map[string]*failEntry
}

type failEntry struct {
	count       int
	firstFail   time.Time
	lockedUntil time.Time
	lockouts    int
}

func NewFailureLimiter(max int, window, lock, maxLock time.Duration) *FailureLimiter {
	return &FailureLimiter{max: max, window: window, baseLck: lock, maxLock: maxLock, now: time.Now, m: map[string]*failEntry{}}
}

// Check reports whether key is currently locked, and for how long.
func (l *FailureLimiter) Check(key string) (locked bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[key]
	if !ok {
		return false, 0
	}
	if now := l.now(); now.Before(e.lockedUntil) {
		return true, e.lockedUntil.Sub(now)
	}
	return false, 0
}

// Fail records a failure and returns true if this failure triggered a lockout.
func (l *FailureLimiter) Fail(key string) (nowLocked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.gc(now)
	e, ok := l.m[key]
	if !ok {
		e = &failEntry{}
		l.m[key] = e
	}
	if e.count == 0 || now.Sub(e.firstFail) > l.window {
		e.count, e.firstFail = 0, now
	}
	e.count++
	if e.count >= l.max {
		d := l.baseLck << uint(e.lockouts)
		if d > l.maxLock || d <= 0 {
			d = l.maxLock
		}
		e.lockedUntil = now.Add(d)
		e.lockouts++
		e.count = 0
		return true
	}
	return false
}

// Success clears the failure counter (not the escalation history).
func (l *FailureLimiter) Success(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.m[key]; ok {
		e.count = 0
	}
}

// gc drops stale entries so the map cannot grow without bound.
func (l *FailureLimiter) gc(now time.Time) {
	if len(l.m) < 1000 {
		return
	}
	for k, e := range l.m {
		if now.After(e.lockedUntil) && now.Sub(e.firstFail) > l.window+l.maxLock {
			delete(l.m, k)
		}
	}
}

// clientIP returns the peer address. X-Forwarded-For is only honoured
// when VAULT_TRUST_PROXY=true (i.e. you run behind your own reverse
// proxy); otherwise it is attacker-controlled and ignored.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
