package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessionAbsoluteTTL = 12 * time.Hour
	sessionIdleTTL     = 30 * time.Minute
	pendingMFATTL      = 5 * time.Minute
	pendingMFAMaxTries = 5
)

// SessionStore is an in-memory bearer-token session table. Tokens are
// opaque random strings (not JWTs). Only a SHA-256 of each token is kept
// in memory, sessions expire both absolutely and after idling, and a
// background janitor removes expired entries.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
	pending  map[string]*pendingMFA
	now      func() time.Time
}

type session struct {
	UserID    string
	MFA       bool // true if this session passed a second factor
	Created   time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

// pendingMFA is the half-authenticated state between "password OK" and
// "second factor OK". It grants nothing except the right to submit a code.
type pendingMFA struct {
	UserID    string
	ExpiresAt time.Time
	Attempts  int
}

func NewSessionStore() *SessionStore {
	s := &SessionStore{sessions: map[string]*session{}, pending: map[string]*pendingMFA{}, now: time.Now}
	go func() {
		t := time.NewTicker(time.Minute)
		for range t.C {
			s.Cleanup()
		}
	}()
	return s
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *SessionStore) Create(userID string, mfa bool) string {
	token := randomToken()
	now := s.now()
	s.mu.Lock()
	s.sessions[tokenKey(token)] = &session{UserID: userID, MFA: mfa, Created: now, LastSeen: now, ExpiresAt: now.Add(sessionAbsoluteTTL)}
	s.mu.Unlock()
	return token
}

// Get returns the live session for token and refreshes its idle timer.
func (s *SessionStore) Get(token string) (session, bool) {
	k := tokenKey(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[k]
	if !ok {
		return session{}, false
	}
	now := s.now()
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeen) > sessionIdleTTL {
		delete(s.sessions, k)
		return session{}, false
	}
	sess.LastSeen = now
	return *sess, true
}

func (s *SessionStore) MarkMFA(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[tokenKey(token)]; ok {
		sess.MFA = true
	}
}

func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	delete(s.sessions, tokenKey(token))
	s.mu.Unlock()
}

// DeleteUser revokes every session of a user (used when MFA is reset).
func (s *SessionStore) DeleteUser(userID string) {
	s.mu.Lock()
	for k, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, k)
		}
	}
	s.mu.Unlock()
}

func (s *SessionStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Cleanup removes expired sessions and pending MFA challenges.
func (s *SessionStore) Cleanup() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sess := range s.sessions {
		if now.After(sess.ExpiresAt) || now.Sub(sess.LastSeen) > sessionIdleTTL {
			delete(s.sessions, k)
		}
	}
	for k, p := range s.pending {
		if now.After(p.ExpiresAt) {
			delete(s.pending, k)
		}
	}
}

func (s *SessionStore) CreatePending(userID string) string {
	token := randomToken()
	s.mu.Lock()
	s.pending[tokenKey(token)] = &pendingMFA{UserID: userID, ExpiresAt: s.now().Add(pendingMFATTL)}
	s.mu.Unlock()
	return token
}

func (s *SessionStore) PendingUser(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[tokenKey(token)]
	if !ok || s.now().After(p.ExpiresAt) {
		delete(s.pending, tokenKey(token))
		return "", false
	}
	return p.UserID, true
}

// FailPending counts a wrong code; after too many the challenge is burned.
func (s *SessionStore) FailPending(token string) (burned bool) {
	k := tokenKey(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[k]
	if !ok {
		return true
	}
	p.Attempts++
	if p.Attempts >= pendingMFAMaxTries {
		delete(s.pending, k)
		return true
	}
	return false
}

func (s *SessionStore) DeletePending(token string) {
	s.mu.Lock()
	delete(s.pending, tokenKey(token))
	s.mu.Unlock()
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// Principal is an authenticated caller: the user plus facts about the
// session they are using.
type Principal struct {
	User  *User
	MFA   bool   // this session has passed a second factor
	Token string // raw bearer token (needed for logout / marking MFA)
}

// Paths a user may call before completing mandatory MFA enrolment.
func allowedBeforeMFAEnrolment(path string) bool {
	switch path {
	case "/api/me", "/api/logout", "/api/mfa/setup", "/api/mfa/enable":
		return true
	}
	return false
}

// authenticate resolves the caller from the bearer token, or writes 401
// and returns ok=false. When VAULT_REQUIRE_MFA is on, users without MFA
// are confined to the enrolment endpoints.
func (a *App) authenticate(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return nil, false
	}
	sess, ok := a.sessions.Get(token)
	if !ok {
		writeError(w, http.StatusUnauthorized, "session expired or invalid")
		return nil, false
	}
	user, ok := a.store.UserByID(sess.UserID)
	if !ok {
		a.sessions.Delete(token)
		writeError(w, http.StatusUnauthorized, "user no longer exists")
		return nil, false
	}
	if a.requireMFA && !user.MFAEnabled && !allowedBeforeMFAEnrolment(r.URL.Path) {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"error": "multi-factor authentication enrolment is required before using the vault", "mfaSetupRequired": true,
		})
		return nil, false
	}
	return &Principal{User: user, MFA: sess.MFA, Token: token}, true
}

// requireRole additionally enforces an administrative role for
// management endpoints (user / policy / audit). This is separate from the
// resource-level policy engine in policy.go, which applies to everyone
// including administrators.
func (a *App) requireRole(w http.ResponseWriter, r *http.Request, allowed ...Role) (*Principal, bool) {
	p, ok := a.authenticate(w, r)
	if !ok {
		return nil, false
	}
	for _, role := range allowed {
		if p.User.Role == role {
			return p, true
		}
	}
	writeError(w, http.StatusForbidden, "role "+string(p.User.Role)+" is not permitted to perform this action")
	return nil, false
}
