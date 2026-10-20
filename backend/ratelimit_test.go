package main

import (
	"testing"
	"time"
)

func TestLockoutAndEscalation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewFailureLimiter(5, 15*time.Minute, 15*time.Minute, time.Hour)
	l.now = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		if l.Fail("k") {
			t.Fatal("locked too early")
		}
	}
	if locked, _ := l.Check("k"); locked {
		t.Fatal("locked before limit")
	}
	if !l.Fail("k") {
		t.Fatal("5th failure should lock")
	}
	if locked, retry := l.Check("k"); !locked || retry != 15*time.Minute {
		t.Fatalf("expected 15m lock, got %v %v", locked, retry)
	}
	now = now.Add(16 * time.Minute)
	if locked, _ := l.Check("k"); locked {
		t.Fatal("lock should have expired")
	}
	for i := 0; i < 5; i++ {
		l.Fail("k")
	}
	if _, retry := l.Check("k"); retry != 30*time.Minute {
		t.Fatalf("second lockout should double, got %v", retry)
	}
}

func TestFailuresOutsideWindowDontAccumulate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewFailureLimiter(3, time.Minute, time.Minute, time.Hour)
	l.now = func() time.Time { return now }
	l.Fail("k")
	l.Fail("k")
	now = now.Add(2 * time.Minute)
	if l.Fail("k") {
		t.Fatal("old failures should have aged out")
	}
}

func TestSuccessResetsCounter(t *testing.T) {
	l := NewFailureLimiter(3, time.Minute, time.Minute, time.Hour)
	l.Fail("k")
	l.Fail("k")
	l.Success("k")
	if l.Fail("k") {
		t.Fatal("success should reset the counter")
	}
}

func TestSessionExpiryAndCleanup(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := &SessionStore{sessions: map[string]*session{}, pending: map[string]*pendingMFA{}, now: func() time.Time { return now }}
	tok := s.Create("u1", false)
	if _, ok := s.Get(tok); !ok {
		t.Fatal("fresh session invalid")
	}
	now = now.Add(sessionIdleTTL + time.Minute)
	if _, ok := s.Get(tok); ok {
		t.Fatal("idle session should expire")
	}
	tok2 := s.Create("u2", false)
	s.CreatePending("u3")
	now = now.Add(sessionAbsoluteTTL + time.Minute)
	s.Cleanup()
	if s.Count() != 0 || len(s.pending) != 0 {
		t.Fatal("cleanup left expired entries behind")
	}
	if _, ok := s.Get(tok2); ok {
		t.Fatal("expired session valid")
	}
	// logout
	now = now.Add(0)
	tok3 := s.Create("u4", true)
	s.Delete(tok3)
	if _, ok := s.Get(tok3); ok {
		t.Fatal("deleted session valid")
	}
}

func TestPendingMFABurnsAfterAttempts(t *testing.T) {
	s := NewSessionStore()
	tok := s.CreatePending("u")
	for i := 0; i < pendingMFAMaxTries-1; i++ {
		if s.FailPending(tok) {
			t.Fatal("burned too early")
		}
	}
	if !s.FailPending(tok) {
		t.Fatal("should burn at max attempts")
	}
	if _, ok := s.PendingUser(tok); ok {
		t.Fatal("burned challenge still valid")
	}
}
