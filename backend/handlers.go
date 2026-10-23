package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	// NEW: replace YOUR_MODULE with the module name on the first line of go.mod
	"vault/validator"
)

// EventUploadRejected is the audit action written when the upload validator
// refuses a file. (Move this next to your other Event* constants in audit.go
// if you prefer to keep them together.)
const EventUploadRejected Action = "UPLOAD_REJECTED"

// Config holds runtime options (all from environment variables).
type Config struct {
	RequireMFA       bool   // VAULT_REQUIRE_MFA: every user must enrol MFA before using the vault
	HideUnauthorized bool   // VAULT_HIDE_UNAUTHORIZED: file lists only show files the caller's role has a policy for
	TrustProxy       bool   // VAULT_TRUST_PROXY: honour X-Forwarded-For for rate limiting
	MaxUploadBytes   int64  // VAULT_MAX_UPLOAD_MB
	MFAIssuer        string // VAULT_MFA_ISSUER

	// NEW: upload validation
	QuarantineDir string // VAULT_QUARANTINE_DIR: private folder where uploads sit while being checked
	ClamAVAddr    string // VAULT_CLAMAV_ADDR: host:port of clamd (e.g. clamav:3310); empty = malware scan disabled
}

func envBool(name string) bool {
	v := strings.ToLower(os.Getenv(name))
	return v == "1" || v == "true" || v == "yes"
}

func LoadConfig() Config {
	mb := int64(200)
	if v, err := strconv.ParseInt(os.Getenv("VAULT_MAX_UPLOAD_MB"), 10, 64); err == nil && v > 0 {
		mb = v
	}
	issuer := os.Getenv("VAULT_MFA_ISSUER")
	if issuer == "" {
		issuer = "Zero-Trust Vault"
	}
	return Config{
		RequireMFA:       envBool("VAULT_REQUIRE_MFA"),
		HideUnauthorized: envBool("VAULT_HIDE_UNAUTHORIZED"),
		TrustProxy:       envBool("VAULT_TRUST_PROXY"),
		MaxUploadBytes:   mb << 20,
		MFAIssuer:        issuer,
		QuarantineDir:    strings.TrimSpace(os.Getenv("VAULT_QUARANTINE_DIR")),
		ClamAVAddr:       strings.TrimSpace(os.Getenv("VAULT_CLAMAV_ADDR")),
	}
}

type App struct {
	store    *Store
	sessions *SessionStore
	km       *KeyManager
	cfg      Config

	userLim *FailureLimiter // failed logins / MFA codes per username
	ipLim   *FailureLimiter // failed logins per client IP

	requireMFA bool

	fileValidator *validator.Validator // NEW: checks every upload before encryption
}

func NewApp(store *Store, km *KeyManager, cfg Config) *App {
	if cfg.QuarantineDir == "" {
		cfg.QuarantineDir = filepath.Join(os.TempDir(), "vault-quarantine")
	}
	return &App{
		store: store, km: km, cfg: cfg,
		sessions:      NewSessionStore(),
		userLim:       NewFailureLimiter(5, 15*time.Minute, 15*time.Minute, time.Hour),
		ipLim:         NewFailureLimiter(20, 15*time.Minute, 15*time.Minute, time.Hour),
		requireMFA:    cfg.RequireMFA,
		fileValidator: newFileValidator(cfg),
	}
}

// newFileValidator prepares the quarantine folder and builds the validator.
func newFileValidator(cfg Config) *validator.Validator {
	if err := os.MkdirAll(cfg.QuarantineDir, 0o700); err != nil {
		log.Fatalf("cannot create quarantine dir %q: %v", cfg.QuarantineDir, err)
	}
	purgeQuarantine(cfg.QuarantineDir, time.Hour) // leftovers from a crash

	v := &validator.Validator{MaxSize: cfg.MaxUploadBytes}
	if cfg.ClamAVAddr != "" {
		v.Scanner = &validator.ClamAV{Network: "tcp", Addr: cfg.ClamAVAddr, Timeout: 3 * time.Minute}
	} else {
		log.Printf("WARNING: VAULT_CLAMAV_ADDR is not set - malware scanning is DISABLED (type/corruption checks still run)")
	}
	return v
}

func purgeQuarantine(dir string, olderThan time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > olderThan {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, base64.RawURLEncoding.EncodeToString(b))
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// cleanText strips control characters and caps length — used for
// attacker-supplied strings (e.g. attempted usernames) before they are
// written to the audit log.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

// audit writes an event and, on failure, refuses the request (fail closed).
func (a *App) audit(w http.ResponseWriter, u *User, resID, resName string, action Action, d Decision, reason string) bool {
	if err := LogAudit(a.store, u, resID, resName, action, d, reason); err != nil {
		log.Printf("AUDIT WRITE FAILED (%s %s): %v", action, d, err)
		writeError(w, http.StatusInternalServerError, "audit trail unavailable — request refused")
		return false
	}
	return true
}

// auditBestEffort is for events where we are already denying/ending the
// request; failures are logged loudly but cannot make things less safe.
func (a *App) auditBestEffort(u *User, resID, resName string, action Action, d Decision, reason string) {
	if err := LogAudit(a.store, u, resID, resName, action, d, reason); err != nil {
		log.Printf("AUDIT WRITE FAILED (%s %s): %v", action, d, err)
	}
}

func (a *App) auditAnon(username string, action Action, d Decision, reason string) {
	if err := LogEvent(a.store, "", cleanText(username, 64), "", "", "", action, d, reason); err != nil {
		log.Printf("AUDIT WRITE FAILED (%s %s): %v", action, d, err)
	}
}

// --- Auth ---

func tooMany(w http.ResponseWriter, retry time.Duration) {
	secs := int(retry.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
		"error": "too many failed attempts — try again later", "retryAfterSeconds": secs,
	})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	uname := strings.ToLower(strings.TrimSpace(req.Username))
	ukey, ipKey := "user:"+uname, "ip:"+clientIP(r, a.cfg.TrustProxy)

	for _, k := range []struct {
		lim *FailureLimiter
		key string
	}{{a.userLim, ukey}, {a.ipLim, ipKey}} {
		if locked, retry := k.lim.Check(k.key); locked {
			a.auditAnon(req.Username, EventLogin, DecisionDeny, "rejected: too many failed attempts ("+k.key[:strings.Index(k.key, ":")]+" locked)")
			tooMany(w, retry)
			return
		}
	}

	user, found := a.store.UserByUsername(strings.TrimSpace(req.Username))
	ok, rehash := false, false
	if found {
		ok, rehash = VerifyPassword(req.Password, user.PasswordHash, user.Salt)
	} else {
		burnPasswordTime(req.Password)
	}
	if !ok {
		lockedU := a.userLim.Fail(ukey)
		lockedI := a.ipLim.Fail(ipKey)
		reason := "invalid username or password"
		if lockedU || lockedI {
			reason += " — lockout triggered"
		}
		a.auditAnon(req.Username, EventLogin, DecisionDeny, reason)
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if rehash {
		if h, err := HashPassword(req.Password); err == nil {
			_ = a.store.UpdatePasswordHash(user.ID, h)
		}
	}

	if user.MFAEnabled {
		// Password alone is not enough: hand out a short-lived challenge.
		if !a.audit(w, user, "", "", EventLogin, DecisionAllow, "password verified; MFA challenge issued") {
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mfaRequired": true, "mfaToken": a.sessions.CreatePending(user.ID),
		})
		return
	}
	a.userLim.Success(ukey)
	a.ipLim.Success(ipKey)
	if !a.audit(w, user, "", "", EventLogin, DecisionAllow, "login succeeded (password only)") {
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": a.sessions.Create(user.ID, false), "user": user.Safe(),
		"mfaSetupRequired": a.requireMFA,
	})
}

// verifySecondFactor accepts a TOTP code or a one-time recovery code.
func (a *App) verifySecondFactor(user *User, code string) (bool, string) {
	if LooksLikeRecoveryCode(code) {
		ok, err := a.store.ConsumeRecoveryCode(user.ID, HashRecoveryCode(code))
		return ok && err == nil, "recovery code"
	}
	secret, err := a.km.Open(user.MFASecretEnc, mfaAAD(user.ID))
	if err != nil {
		return false, "totp"
	}
	step, ok := VerifyTOTP(string(secret), code, time.Now(), user.MFALastStep)
	if !ok {
		return false, "totp"
	}
	adv, err := a.store.AdvanceMFAStep(user.ID, step)
	return adv && err == nil, "totp"
}

func (a *App) handleLoginMFA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MFAToken string `json:"mfaToken"`
		Code     string `json:"code"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.MFAToken == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "mfaToken and code are required")
		return
	}
	userID, ok := a.sessions.PendingUser(req.MFAToken)
	if !ok {
		writeError(w, http.StatusUnauthorized, "MFA challenge expired — sign in again")
		return
	}
	user, ok := a.store.UserByID(userID)
	if !ok || !user.MFAEnabled {
		writeError(w, http.StatusUnauthorized, "MFA challenge invalid — sign in again")
		return
	}
	ukey, ipKey := "user:"+strings.ToLower(user.Username), "ip:"+clientIP(r, a.cfg.TrustProxy)
	if locked, retry := a.userLim.Check(ukey); locked {
		a.auditBestEffort(user, "", "", EventMFAVerify, DecisionDeny, "rejected: account temporarily locked")
		tooMany(w, retry)
		return
	}
	if locked, retry := a.ipLim.Check(ipKey); locked {
		tooMany(w, retry)
		return
	}
	good, method := a.verifySecondFactor(user, req.Code)
	if !good {
		lockedU := a.userLim.Fail(ukey)
		a.ipLim.Fail(ipKey)
		burned := a.sessions.FailPending(req.MFAToken)
		reason := "invalid " + method
		if lockedU {
			reason += " — lockout triggered"
		}
		if burned {
			reason += " — challenge invalidated"
		}
		a.auditBestEffort(user, "", "", EventMFAVerify, DecisionDeny, reason)
		writeError(w, http.StatusUnauthorized, "invalid verification code")
		return
	}
	a.sessions.DeletePending(req.MFAToken)
	a.userLim.Success(ukey)
	a.ipLim.Success(ipKey)
	if !a.audit(w, user, "", "", EventMFAVerify, DecisionAllow, "second factor verified ("+method+"); session established") {
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": a.sessions.Create(user.ID, true), "user": user.Safe(),
	})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	a.auditBestEffort(p.User, "", "", EventLogout, DecisionAllow, "session ended by user")
	a.sessions.Delete(p.Token)
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, struct {
		SafeUser
		MFAVerified      bool `json:"mfaVerified"`
		MFASetupRequired bool `json:"mfaSetupRequired"`
	}{p.User.Safe(), p.MFA, a.requireMFA && !p.User.MFAEnabled})
}

// --- Users (admin only) ---

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,64}$`)

func (a *App) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	p, ok := a.requireRole(w, r, RoleAdmin)
	if !ok {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     Role   `json:"role"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if !usernameRe.MatchString(req.Username) {
		writeError(w, http.StatusBadRequest, "username must be 3-64 characters: letters, digits, '.', '_' or '-'")
		return
	}
	if !IsValidRole(req.Role) {
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}
	if err := ValidatePasswordStrength(req.Username, req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, exists := a.store.UserByUsername(req.Username); exists {
		writeError(w, http.StatusConflict, "username already exists")
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	user := &User{ID: newID("user"), Username: req.Username, PasswordHash: hash, Role: req.Role, CreatedAt: time.Now()}
	if !a.audit(w, p.User, user.ID, user.Username, EventUserCreate, DecisionAllow,
		fmt.Sprintf("created user %q with role %s", user.Username, user.Role)) {
		return
	}
	if err := a.store.CreateUser(user); err != nil {
		a.auditBestEffort(p.User, user.ID, user.Username, EventUserCreate, DecisionDeny, "creation failed: "+err.Error())
		if errors.Is(err, ErrConflict) {
			writeError(w, http.StatusConflict, "username already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to save user")
		return
	}
	writeJSON(w, http.StatusCreated, user.Safe())
}

func (a *App) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireRole(w, r, RoleAdmin); !ok {
		return
	}
	users := a.store.ListUsers()
	out := make([]SafeUser, 0, len(users))
	for _, u := range users {
		out = append(out, u.Safe())
	}
	writeJSON(w, http.StatusOK, out)
}

// --- Files ---

func extendDeadlines(w http.ResponseWriter, d time.Duration) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(d))
	_ = rc.SetWriteDeadline(time.Now().Add(d))
}

func safeFileName(n string) string {
	n = cleanText(filepath.Base(strings.ReplaceAll(n, "\\", "/")), 200)
	if n == "" || n == "." || n == "/" || n == ".." {
		return "unnamed"
	}
	return n
}

// handleUploadFile reads the multipart upload and hands the file to
// storeUpload, which quarantines it, validates it, and only then encrypts it.
// The multipart "classification" field must come BEFORE the "file" field.
func (a *App) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	p, ok := a.requireRole(w, r, RoleAdmin)
	if !ok {
		return
	}
	extendDeadlines(w, 30*time.Minute)
	r.Body = http.MaxBytesReader(w, r.Body, a.cfg.MaxUploadBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, "expected multipart/form-data")
		return
	}
	var class Classification
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			writeError(w, http.StatusBadRequest, "missing file field")
			return
		}
		if err != nil {
			a.uploadReadError(w, err)
			return
		}
		switch part.FormName() {
		case "classification":
			b, _ := io.ReadAll(io.LimitReader(part, 64))
			class = Classification(strings.TrimSpace(string(b)))
		case "file":
			if !IsValidClassification(class) {
				writeError(w, http.StatusBadRequest, "a valid classification field must be sent before the file field")
				return
			}
			a.storeUpload(w, r, p, class, safeFileName(part.FileName()), part)
			return
		}
	}
}

func (a *App) uploadReadError(w http.ResponseWriter, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("file exceeds the %d MB limit", a.cfg.MaxUploadBytes>>20))
		return
	}
	writeError(w, http.StatusBadRequest, "failed to read upload")
}

// storeUpload is the secure upload pipeline:
//
//	1. QUARANTINE : copy the upload to a private temp file (0600, deleted at the end)
//	2. VALIDATE   : size, extension, real type, corruption, active content, ClamAV
//	                -> rejected? audit UPLOAD_REJECTED, delete temp file, stop.
//	3. ENCRYPT    : only a validated file is encrypted (and re-hashed while reading,
//	                so we know the bytes encrypted are the bytes that were checked)
//	4. AUDIT+SAVE : audit FILE_UPLOAD (with type + sha256), then write metadata
func (a *App) storeUpload(w http.ResponseWriter, r *http.Request, p *Principal, class Classification, name string, src io.Reader) {
	// ---- 1. QUARANTINE ----
	q, err := os.CreateTemp(a.cfg.QuarantineDir, "q-*") // created with mode 0600
	if err != nil {
		log.Printf("quarantine create failed: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to create quarantine file")
		return
	}
	qPath := q.Name()
	defer os.Remove(qPath) // plaintext never outlives this request
	if _, err := io.Copy(q, src); err != nil {
		q.Close()
		a.uploadReadError(w, err)
		return
	}
	if err := q.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write quarantine file")
		return
	}

	// ---- 2. VALIDATE ----
	vres, err := a.fileValidator.Validate(r.Context(), qPath, name)
	if err != nil {
		var rej *validator.RejectError
		if errors.As(err, &rej) {
			// The file itself is bad: audit the denial and refuse.
			reason := cleanText(fmt.Sprintf("upload of %q rejected: %s - %s", name, rej.Code, rej.Reason), 300)
			a.auditBestEffort(p.User, "", name, EventUploadRejected, DecisionDeny, reason)
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error":  "file rejected by security validation",
				"code":   rej.Code,
				"reason": cleanText(rej.Reason, 200),
			})
			return
		}
		// Scanner down / I/O problem: FAIL CLOSED - the file is not accepted.
		log.Printf("upload validation unavailable for %q: %v", name, err)
		a.auditBestEffort(p.User, "", name, EventUploadRejected, DecisionDeny,
			cleanText(fmt.Sprintf("upload of %q refused: validation unavailable (%v)", name, err), 300))
		writeError(w, http.StatusServiceUnavailable, "file could not be verified - upload refused, try again later")
		return
	}

	// ---- 3. ENCRYPT (only reached when the file passed every check) ----
	in, err := os.Open(qPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read quarantine file")
		return
	}
	defer in.Close()

	id := newID("file")
	encPath := filepath.Join(a.store.FilesDir(), id+".enc")
	f, err := os.OpenFile(encPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create encrypted file")
		return
	}
	cleanup := func() { f.Close(); os.Remove(encPath) }
	bw := bufio.NewWriterSize(f, 256<<10)
	h := sha256.New()
	size, wrapped, err := EncryptStream(a.km, bw, io.TeeReader(in, h), id, class)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		cleanup()
		log.Printf("encryption of %s failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, "failed to encrypt file")
		return
	}
	// Make sure the bytes we encrypted are exactly the bytes we validated.
	if hex.EncodeToString(h.Sum(nil)) != vres.SHA256 {
		cleanup()
		a.auditBestEffort(p.User, "", name, EventUploadRejected, DecisionDeny,
			cleanText(fmt.Sprintf("upload of %q refused: file changed after validation", name), 300))
		writeError(w, http.StatusInternalServerError, "file changed during processing - upload refused")
		return
	}
	if err := f.Close(); err != nil {
		os.Remove(encPath)
		writeError(w, http.StatusInternalServerError, "failed to persist encrypted file")
		return
	}

	// ---- 4. AUDIT + SAVE ----
	res := &FileResource{
		ID: id, Name: name, Classification: class, OwnerID: p.User.ID, EncPath: encPath,
		WrappedKey: wrapped, EncVersion: 2, Size: size, UploadedAt: time.Now(),
	}
	if !a.audit(w, p.User, id, name, EventFileUpload, DecisionAllow,
		fmt.Sprintf("uploaded %q (%d bytes) classified %s; validated as %s, sha256=%s",
			name, size, class, vres.Kind, vres.SHA256)) {
		os.Remove(encPath)
		return
	}
	if err := a.store.CreateFile(res); err != nil {
		os.Remove(encPath)
		a.auditBestEffort(p.User, id, name, EventFileUpload, DecisionDeny, "metadata save failed: "+err.Error())
		writeError(w, http.StatusInternalServerError, "failed to save file metadata")
		return
	}
	writeJSON(w, http.StatusCreated, res.View())
}

func (a *App) handleListFiles(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	files := a.store.ListFiles()
	out := make([]FileView, 0, len(files))
	for _, f := range files {
		if a.cfg.HideUnauthorized && p.User.Role != RoleAdmin {
			if !RoleClearanceOK(p.User.Role, f.Classification) || !hasPolicyForRole(a.store, f.ID, p.User.Role) {
				continue
			}
		}
		out = append(out, f.View())
	}
	writeJSON(w, http.StatusOK, out)
}

func hasPolicyForRole(pr PolicyReader, fileID string, role Role) bool {
	for _, pol := range pr.PoliciesForResource(fileID) {
		if pol.Role == role {
			return true
		}
	}
	return false
}

const readPreviewLimit = 64 << 10 // READ returns at most 64 KiB; DOWNLOAD returns everything

// handleAccessFile evaluates a Zero-Trust access request:
// identity + role + clearance + classification + MFA assurance +
// action + policy -> explicit ALLOW/DENY, always audited BEFORE any data
// is released or removed.
//
//	READ     -> first 64 KiB of the decrypted file (preview)
//	DOWNLOAD -> the complete decrypted file
//	DELETE   -> deletes the file; never returns its contents
func (a *App) handleAccessFile(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	file, ok := a.store.FileByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "resource not found")
		return
	}
	var req struct {
		Action Action `json:"action"`
	}
	if err := decodeJSON(w, r, &req); err != nil || !IsFileAction(req.Action) {
		writeError(w, http.StatusBadRequest, "missing or unsupported action (READ, DOWNLOAD or DELETE)")
		return
	}

	decision, reason := EvaluateAccess(a.store, p.User, file, req.Action, AccessContext{MFAVerified: p.MFA})
	if !a.audit(w, p.User, file.ID, file.Name, req.Action, decision, reason) {
		return // fail closed: no audit record, no access
	}
	if decision == DecisionDeny {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{"decision": decision, "reason": reason})
		return
	}
	if req.Action == ActionDelete {
		a.deleteFile(w, p, file, reason)
		return
	}
	a.streamFile(w, p, file, req.Action, reason)
}

func (a *App) deleteFile(w http.ResponseWriter, p *Principal, file *FileResource, reason string) {
	if err := a.store.DeleteFile(file.ID); err != nil {
		a.auditBestEffort(p.User, file.ID, file.Name, ActionDelete, DecisionDeny, "delete failed: "+err.Error())
		writeError(w, http.StatusInternalServerError, "failed to delete file")
		return
	}
	if err := os.Remove(file.EncPath); err != nil && !os.IsNotExist(err) {
		log.Printf("deleted %s from database but could not remove %s: %v", file.ID, file.EncPath, err)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"decision": DecisionAllow, "reason": reason, "deleted": true, "fileName": file.Name,
	})
}

func (a *App) streamFile(w http.ResponseWriter, p *Principal, file *FileResource, action Action, reason string) {
	extendDeadlines(w, 30*time.Minute)
	rd, err := OpenFile(a.km, file)
	if err != nil {
		a.auditBestEffort(p.User, file.ID, file.Name, EventIntegrityFail, DecisionDeny, "open failed: "+err.Error())
		writeError(w, http.StatusInternalServerError, "failed to read encrypted resource")
		return
	}
	defer rd.Close()
	br := bufio.NewReaderSize(rd, chunkSize)
	// Force the first chunk to decrypt (and authenticate) BEFORE any header is sent.
	if _, err := br.Peek(1); err != nil && err != io.EOF {
		a.auditBestEffort(p.User, file.ID, file.Name, EventIntegrityFail, DecisionDeny, "integrity check failed: "+err.Error())
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	var src io.Reader = br
	truncated := false
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": file.Name}))
	h.Set("X-Vault-Decision", string(DecisionAllow))
	h.Set("X-Vault-Reason", url.QueryEscape(reason))
	h.Set("X-Vault-FileName", url.QueryEscape(file.Name))
	if action == ActionRead {
		src = io.LimitReader(br, readPreviewLimit)
		truncated = file.Size > readPreviewLimit
	} else {
		h.Set("Content-Length", strconv.FormatInt(file.Size, 10))
	}
	h.Set("X-Vault-Truncated", strconv.FormatBool(truncated))
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, src); err != nil {
		a.auditBestEffort(p.User, file.ID, file.Name, EventIntegrityFail, DecisionDeny, "stream aborted: "+err.Error())
		log.Printf("stream of %s aborted: %v", file.ID, err)
		panic(http.ErrAbortHandler) // never end a failed stream like a successful one
	}
}

// --- Policies (admin only) ---

func (a *App) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := a.requireRole(w, r, RoleAdmin)
	if !ok {
		return
	}
	var req struct {
		ResourceID string   `json:"resourceId"`
		Role       Role     `json:"role"`
		Actions    []Action `json:"actions"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	file, ok := a.store.FileByID(req.ResourceID)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown resource")
		return
	}
	if !IsValidRole(req.Role) {
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}
	if len(req.Actions) == 0 {
		writeError(w, http.StatusBadRequest, "at least one action is required")
		return
	}
	seen := map[Action]bool{}
	actions := make([]Action, 0, len(req.Actions))
	for _, act := range req.Actions {
		if !IsFileAction(act) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid action %q (allowed: READ, DOWNLOAD, DELETE)", act))
			return
		}
		if !seen[act] {
			seen[act] = true
			actions = append(actions, act)
		}
	}
	if !RoleClearanceOK(req.Role, file.Classification) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"role %s is not cleared for %s data; a policy cannot grant it access", req.Role, file.Classification))
		return
	}
	if hasPolicyForRole(a.store, file.ID, req.Role) {
		writeError(w, http.StatusConflict, "a policy for this role and resource already exists — delete it first")
		return
	}
	pol := &Policy{ID: newID("policy"), ResourceID: file.ID, Role: req.Role, Actions: actions, CreatedAt: time.Now()}
	if !a.audit(w, p.User, file.ID, file.Name, EventPolicyCreate, DecisionAllow,
		fmt.Sprintf("granted role %s %v on %q (%s)", pol.Role, pol.Actions, file.Name, file.Classification)) {
		return
	}
	if err := a.store.CreatePolicy(pol); err != nil {
		a.auditBestEffort(p.User, file.ID, file.Name, EventPolicyCreate, DecisionDeny, "save failed: "+err.Error())
		if errors.Is(err, ErrConflict) {
			writeError(w, http.StatusConflict, "a policy for this role and resource already exists — delete it first")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to save policy")
		return
	}
	writeJSON(w, http.StatusCreated, pol)
}

func (a *App) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireRole(w, r, RoleAdmin); !ok {
		return
	}
	writeJSON(w, http.StatusOK, a.store.ListPolicies())
}

func (a *App) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	p, ok := a.requireRole(w, r, RoleAdmin)
	if !ok {
		return
	}
	pol, ok := a.store.PolicyByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	resName := pol.ResourceID
	if f, ok := a.store.FileByID(pol.ResourceID); ok {
		resName = f.Name
	}
	if !a.audit(w, p.User, pol.ResourceID, resName, EventPolicyDelete, DecisionAllow,
		fmt.Sprintf("revoked role %s %v on %q", pol.Role, pol.Actions, resName)) {
		return
	}
	if _, err := a.store.DeletePolicy(pol.ID); err != nil {
		a.auditBestEffort(p.User, pol.ResourceID, resName, EventPolicyDelete, DecisionDeny, "delete failed: "+err.Error())
		writeError(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Audit & dashboard (admin only) ---

func (a *App) handleListAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireRole(w, r, RoleAdmin); !ok {
		return
	}
	limit, offset := 200, 0
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v >= 0 {
		offset = v
	}
	writeJSON(w, http.StatusOK, a.store.ListAudit(limit, offset))
}

func (a *App) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireRole(w, r, RoleAdmin); !ok {
		return
	}
	entries, err := a.store.ListAuditAsc()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read audit log")
		return
	}
	writeJSON(w, http.StatusOK, VerifyAuditChain(entries))
}

func (a *App) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireRole(w, r, RoleAdmin); !ok {
		return
	}
	files := a.store.ListFiles()
	total, allow, deny := a.store.AuditCounts()
	byClass := map[Classification]int{}
	for _, f := range files {
		byClass[f.Classification]++
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"totalUsers":            len(a.store.ListUsers()),
		"totalFiles":            len(files),
		"totalPolicies":         len(a.store.ListPolicies()),
		"totalAuditEvents":      total,
		"allowCount":            allow,
		"denyCount":             deny,
		"filesByClassification": byClass,
		"recentAudit":           a.store.ListAudit(8, 0),
	})
}