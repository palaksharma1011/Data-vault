package main

// End-to-end tests against a real PostgreSQL. They are skipped unless
// TEST_DATABASE_URL is set, e.g.
//   TEST_DATABASE_URL=postgres://vault:vault@localhost:5432/vault_test?sslmode=disable go test ./...
// WARNING: the test wipes the `public` schema of that database.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type env struct {
	t     *testing.T
	app   *App
	srv   *httptest.Server
	store *Store
	pool  *pgxpool.Pool
	dir   string
}

func setup(t *testing.T, mutate ...func(*Config)) *env {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := NewStore(dir, dsn)
	if err != nil {
		t.Fatal(err)
	}
	km, _ := NewKeyManager(dir)
	cfg := Config{MaxUploadBytes: 50 << 20, MFAIssuer: "Test"}
	for _, m := range mutate {
		m(&cfg)
	}
	app := NewApp(store, km, cfg)
	srv := httptest.NewServer(app.Routes())
	t.Cleanup(func() { srv.Close(); store.Close(); pool.Close() })
	e := &env{t: t, app: app, srv: srv, store: store, pool: pool, dir: dir}
	e.mkUser("admin", "AdminPass123", RoleAdmin)
	return e
}

func (e *env) mkUser(name, pw string, role Role) *User {
	h, _ := HashPassword(pw)
	u := &User{ID: newID("user"), Username: name, PasswordHash: h, Role: role, CreatedAt: time.Now()}
	if err := e.store.CreateUser(u); err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e *env) req(method, path, token string, body interface{}) (*http.Response, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *env) login(user, pw string) string {
	e.t.Helper()
	resp, b := e.req("POST", "/api/login", "", map[string]string{"username": user, "password": pw})
	if resp.StatusCode != 200 {
		e.t.Fatalf("login %s: %d %s", user, resp.StatusCode, b)
	}
	var out struct{ Token string }
	json.Unmarshal(b, &out)
	if out.Token == "" {
		e.t.Fatalf("login %s: no token (mfa required?) %s", user, b)
	}
	return out.Token
}

func (e *env) upload(token, class, name string, data []byte, classFirst bool) (*http.Response, []byte) {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	writeFile := func() {
		fw, _ := mw.CreateFormFile("file", name)
		fw.Write(data)
	}
	if classFirst {
		mw.WriteField("classification", class)
		writeFile()
	} else {
		writeFile()
		mw.WriteField("classification", class)
	}
	mw.Close()
	r, _ := http.NewRequest("POST", e.srv.URL+"/api/files/upload", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (e *env) mkFile(adminTok, class, name string, data []byte) string {
	e.t.Helper()
	resp, b := e.upload(adminTok, class, name, data, true)
	if resp.StatusCode != 201 {
		e.t.Fatalf("upload: %d %s", resp.StatusCode, b)
	}
	var f FileView
	json.Unmarshal(b, &f)
	return f.ID
}

func (e *env) grant(adminTok, fileID string, role Role, actions ...Action) {
	e.t.Helper()
	resp, b := e.req("POST", "/api/policies", adminTok, map[string]interface{}{"resourceId": fileID, "role": role, "actions": actions})
	if resp.StatusCode != 201 {
		e.t.Fatalf("grant: %d %s", resp.StatusCode, b)
	}
}

func (e *env) access(tok, fileID string, a Action) (*http.Response, []byte) {
	return e.req("POST", "/api/files/"+fileID+"/access", tok, map[string]string{"action": string(a)})
}

func (e *env) auditActions() map[string]int {
	out := map[string]int{}
	for _, a := range e.store.ListAudit(1000, 0) {
		out[string(a.Action)+"/"+string(a.Decision)]++
	}
	return out
}

// ---------- Issue 1: classification is enforced ----------
func TestIssue1_ClassificationEnforced(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	e.mkUser("emp", "EmployeePass1", RoleEmployee)
	id := e.mkFile(adm, "HIGHLY_CONFIDENTIAL", "salaries.txt", []byte("CEO pay: lots"))

	// the API refuses to even create the policy
	resp, _ := e.req("POST", "/api/policies", adm, map[string]interface{}{"resourceId": id, "role": "EMPLOYEE", "actions": []string{"DOWNLOAD"}})
	if resp.StatusCode != 400 {
		t.Fatalf("policy creation should be rejected, got %d", resp.StatusCode)
	}
	// ...and even if a bad policy row exists (inserted straight into the DB), access is denied
	if err := e.store.CreatePolicy(&Policy{ID: "p_bad", ResourceID: id, Role: RoleEmployee, Actions: []Action{ActionDownload}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	tok := e.login("emp", "EmployeePass1")
	resp, body := e.access(tok, id, ActionDownload)
	if resp.StatusCode != 403 || bytes.Contains(body, []byte("CEO pay")) {
		t.Fatalf("employee reached HIGHLY_CONFIDENTIAL data: %d %s", resp.StatusCode, body)
	}
}

// ---------- Issue 2: DELETE deletes and never returns data ----------
func TestIssue2_DeleteDeletesWithoutLeaking(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	e.mkUser("emp", "EmployeePass1", RoleEmployee)
	id := e.mkFile(adm, "INTERNAL", "memo.txt", []byte("INTERNAL-MEMO-BODY"))
	f, _ := e.store.FileByID(id)
	e.grant(adm, id, RoleEmployee, ActionDelete)
	tok := e.login("emp", "EmployeePass1")

	resp, body := e.access(tok, id, ActionDelete)
	if resp.StatusCode != 200 || bytes.Contains(body, []byte("INTERNAL-MEMO-BODY")) || strings.Contains(string(body), "content") {
		t.Fatalf("DELETE leaked data or failed: %d %s", resp.StatusCode, body)
	}
	if _, ok := e.store.FileByID(id); ok {
		t.Fatal("file row still exists after DELETE")
	}
	if _, err := os.Stat(f.EncPath); !os.IsNotExist(err) {
		t.Fatal("ciphertext still on disk after DELETE")
	}
	if len(e.store.PoliciesForResource(id)) != 0 {
		t.Fatal("policies of deleted file remain")
	}
	if resp, _ := e.access(tok, id, ActionDelete); resp.StatusCode != 404 {
		t.Fatalf("second delete should 404, got %d", resp.StatusCode)
	}
}

// ---------- Issue 3: no storage metadata leaks ----------
func TestIssue3_NoMetadataLeak(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	e.mkUser("emp", "EmployeePass1", RoleEmployee)
	e.mkFile(adm, "CONFIDENTIAL", "a.txt", []byte("x"))
	for _, tok := range []string{adm, e.login("emp", "EmployeePass1")} {
		_, body := e.req("GET", "/api/files", tok, nil)
		for _, banned := range []string{"encPath", "wrappedKey", "nonce", ".enc", "ownerId", e.dir} {
			if strings.Contains(string(body), banned) {
				t.Fatalf("file list leaks %q: %s", banned, body)
			}
		}
	}
	// upload response too
	_, b := e.upload(adm, "PUBLIC", "b.txt", []byte("y"), true)
	if strings.Contains(string(b), "encPath") || strings.Contains(string(b), "wrappedKey") {
		t.Fatalf("upload response leaks storage metadata: %s", b)
	}
}

func TestHideUnauthorizedOption(t *testing.T) {
	e := setup(t, func(c *Config) { c.HideUnauthorized = true })
	adm := e.login("admin", "AdminPass123")
	e.mkUser("emp", "EmployeePass1", RoleEmployee)
	visible := e.mkFile(adm, "INTERNAL", "visible.txt", []byte("v"))
	e.mkFile(adm, "INTERNAL", "nogrant.txt", []byte("n"))
	e.mkFile(adm, "HIGHLY_CONFIDENTIAL", "hc.txt", []byte("h"))
	e.grant(adm, visible, RoleEmployee, ActionRead)
	_, body := e.req("GET", "/api/files", e.login("emp", "EmployeePass1"), nil)
	var files []FileView
	json.Unmarshal(body, &files)
	if len(files) != 1 || files[0].ID != visible {
		t.Fatalf("expected only the granted file, got %+v", files)
	}
}

// ---------- Issue 4: input validation ----------
func TestIssue4_PolicyValidation(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	id := e.mkFile(adm, "INTERNAL", "a.txt", []byte("x"))
	bad := []map[string]interface{}{
		{"resourceId": id, "role": "BANANA", "actions": []string{"READ"}},
		{"resourceId": id, "role": "EMPLOYEE", "actions": []string{"FLY"}},
		{"resourceId": id, "role": "EMPLOYEE", "actions": []string{}},
		{"resourceId": "file_nope", "role": "EMPLOYEE", "actions": []string{"READ"}},
	}
	for i, b := range bad {
		if resp, body := e.req("POST", "/api/policies", adm, b); resp.StatusCode != 400 {
			t.Fatalf("case %d should be 400, got %d %s", i, resp.StatusCode, body)
		}
	}
	e.grant(adm, id, RoleEmployee, ActionRead)
	if resp, _ := e.req("POST", "/api/policies", adm, map[string]interface{}{"resourceId": id, "role": "EMPLOYEE", "actions": []string{"READ"}}); resp.StatusCode != 409 {
		t.Fatalf("duplicate policy should be 409, got %d", resp.StatusCode)
	}
	if resp, _ := e.req("DELETE", "/api/policies/policy_missing", adm, nil); resp.StatusCode != 404 {
		t.Fatalf("deleting unknown policy should be 404, got %d", resp.StatusCode)
	}
	// user validation
	for _, u := range []map[string]string{
		{"username": "x", "password": "GoodPass123", "role": "HR"},
		{"username": "bob", "password": "short", "role": "HR"},
		{"username": "bob", "password": "GoodPass123", "role": "KING"},
		{"username": "b ob!", "password": "GoodPass123", "role": "HR"},
	} {
		if resp, body := e.req("POST", "/api/users", adm, u); resp.StatusCode != 400 {
			t.Fatalf("user %v should be 400, got %d %s", u, resp.StatusCode, body)
		}
	}
	if resp, _ := e.req("POST", "/api/users", adm, map[string]string{"username": "good.user", "password": "GoodPass123", "role": "HR"}); resp.StatusCode != 201 {
		t.Fatal("valid user rejected")
	}
}

// ---------- Issue 5: brute-force protection ----------
func TestIssue5_LoginLockout(t *testing.T) {
	e := setup(t)
	e.mkUser("victim", "VictimPass123", RoleEmployee)
	for i := 1; i <= 5; i++ {
		if resp, _ := e.req("POST", "/api/login", "", map[string]string{"username": "victim", "password": "wrong"}); resp.StatusCode != 401 {
			t.Fatalf("attempt %d: want 401 got %d", i, resp.StatusCode)
		}
	}
	resp, body := e.req("POST", "/api/login", "", map[string]string{"username": "victim", "password": "VictimPass123"})
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("correct password must be refused while locked: %d %s", resp.StatusCode, body)
	}
	// unknown usernames are limited too (no user enumeration through lockout behaviour)
	for i := 0; i < 5; i++ {
		e.req("POST", "/api/login", "", map[string]string{"username": "ghost", "password": "x"})
	}
	if resp, _ := e.req("POST", "/api/login", "", map[string]string{"username": "ghost", "password": "x"}); resp.StatusCode != 429 {
		t.Fatalf("unknown user should lock identically, got %d", resp.StatusCode)
	}
}

// ---------- Issue 6: audit coverage + integrity + fail-closed ----------
func TestIssue6_AuditCoverage(t *testing.T) {
	e := setup(t)
	e.req("POST", "/api/login", "", map[string]string{"username": "admin", "password": "wrong"})
	adm := e.login("admin", "AdminPass123")
	e.req("POST", "/api/users", adm, map[string]string{"username": "emp", "password": "EmployeePass1", "role": "EMPLOYEE"})
	id := e.mkFile(adm, "INTERNAL", "a.txt", []byte("x"))
	e.grant(adm, id, RoleEmployee, ActionRead)
	_, pb := e.req("GET", "/api/policies", adm, nil)
	var pols []Policy
	json.Unmarshal(pb, &pols)
	e.req("DELETE", "/api/policies/"+pols[0].ID, adm, nil)
	e.req("POST", "/api/logout", adm, nil)

	got := e.auditActions()
	for _, want := range []string{"LOGIN/DENY", "LOGIN/ALLOW", "USER_CREATE/ALLOW", "FILE_UPLOAD/ALLOW", "POLICY_CREATE/ALLOW", "POLICY_DELETE/ALLOW", "LOGOUT/ALLOW"} {
		if got[want] == 0 {
			t.Errorf("missing audit event %s (have %v)", want, got)
		}
	}
}

func TestAuditTamperEvidenceAndImmutability(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	for i := 0; i < 4; i++ {
		e.req("GET", "/api/me", adm, nil)
		e.mkFile(adm, "PUBLIC", "f.txt", []byte("x"))
	}
	_, body := e.req("GET", "/api/audit/verify", adm, nil)
	var v AuditVerification
	json.Unmarshal(body, &v)
	if !v.OK || v.Checked < 5 {
		t.Fatalf("clean chain should verify: %s", body)
	}
	ctx := context.Background()
	// 1) the database itself refuses edits and deletes
	if _, err := e.pool.Exec(ctx, `UPDATE audit_log SET reason='hacked'`); err == nil {
		t.Fatal("UPDATE on audit_log must be rejected by the trigger")
	}
	if _, err := e.pool.Exec(ctx, `DELETE FROM audit_log`); err == nil {
		t.Fatal("DELETE on audit_log must be rejected by the trigger")
	}
	if _, err := e.pool.Exec(ctx, `TRUNCATE audit_log`); err == nil {
		t.Fatal("TRUNCATE on audit_log must be rejected by the trigger")
	}
	// 2) a privileged attacker who disables the trigger is still caught by the hash chain
	e.pool.Exec(ctx, `ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update`)
	e.pool.Exec(ctx, `UPDATE audit_log SET decision='ALLOW', reason='edited' WHERE seq=(SELECT min(seq)+2 FROM audit_log)`)
	_, body = e.req("GET", "/api/audit/verify", adm, nil)
	json.Unmarshal(body, &v)
	if v.OK || v.BrokenAt == "" {
		t.Fatalf("tampering not detected: %s", body)
	}
}

func TestAuditFailureFailsClosed(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	e.mkUser("emp", "EmployeePass1", RoleEmployee)
	id := e.mkFile(adm, "INTERNAL", "secret.txt", []byte("SENSITIVE-BODY"))
	e.grant(adm, id, RoleEmployee, ActionDownload)
	tok := e.login("emp", "EmployeePass1")

	ctx := context.Background()
	e.pool.Exec(ctx, `ALTER TABLE audit_log RENAME TO audit_log_offline`) // simulate audit outage
	resp, body := e.access(tok, id, ActionDownload)
	e.pool.Exec(ctx, `ALTER TABLE audit_log_offline RENAME TO audit_log`)
	if resp.StatusCode != 500 || bytes.Contains(body, []byte("SENSITIVE-BODY")) {
		t.Fatalf("access must be refused when the audit log is unavailable: %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.access(tok, id, ActionDownload); resp.StatusCode != 200 {
		t.Fatalf("access should work again once audit is back: %d", resp.StatusCode)
	}
}

// ---------- Admin bypass removed ----------
func TestAdminHasNoImplicitAccess(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	id := e.mkFile(adm, "PUBLIC", "p.txt", []byte("public-data"))
	for _, a := range []Action{ActionRead, ActionDownload, ActionDelete} {
		if resp, _ := e.access(adm, id, a); resp.StatusCode != 403 {
			t.Fatalf("admin %s without policy should be 403, got %d", a, resp.StatusCode)
		}
	}
	e.grant(adm, id, RoleAdmin, ActionRead)
	if resp, body := e.access(adm, id, ActionRead); resp.StatusCode != 200 || string(body) != "public-data" {
		t.Fatalf("admin with explicit policy should read: %d %s", resp.StatusCode, body)
	}
}

// ---------- Streaming, AAD on disk, size limits ----------
func TestLargeFileStreamingAndPreview(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	data := make([]byte, 5<<20+777)
	rand.Read(data)
	id := e.mkFile(adm, "INTERNAL", "big.bin", data)
	e.grant(adm, id, RoleAdmin, ActionRead, ActionDownload)

	resp, body := e.access(adm, id, ActionDownload)
	if resp.StatusCode != 200 || sha256.Sum256(body) != sha256.Sum256(data) {
		t.Fatalf("download mismatch: %d (%d bytes)", resp.StatusCode, len(body))
	}
	if resp.Header.Get("Content-Disposition") == "" || resp.Header.Get("X-Vault-Decision") != "ALLOW" {
		t.Fatal("missing response headers")
	}
	resp, body = e.access(adm, id, ActionRead)
	if len(body) != readPreviewLimit || resp.Header.Get("X-Vault-Truncated") != "true" || !bytes.Equal(body, data[:readPreviewLimit]) {
		t.Fatalf("READ should return a 64KiB preview, got %d bytes", len(body))
	}
	// on-disk file is ciphertext
	f, _ := e.store.FileByID(id)
	raw, _ := os.ReadFile(f.EncPath)
	if bytes.Contains(raw, data[1000:1064]) {
		t.Fatal("plaintext found on disk")
	}
	if f.EncVersion != 2 {
		t.Fatal("new files must use enc_version 2")
	}
}

func TestUploadRulesAndLimit(t *testing.T) {
	e := setup(t, func(c *Config) { c.MaxUploadBytes = 1 << 20 })
	adm := e.login("admin", "AdminPass123")
	if resp, _ := e.upload(adm, "PUBLIC", "x", []byte("x"), false); resp.StatusCode != 400 {
		t.Fatalf("file before classification should be 400, got %d", resp.StatusCode)
	}
	if resp, _ := e.upload(adm, "NOPE", "x", []byte("x"), true); resp.StatusCode != 400 {
		t.Fatalf("bad classification should be 400, got %d", resp.StatusCode)
	}
	resp, _ := e.upload(adm, "PUBLIC", "huge", make([]byte, 3<<20), true)
	if resp.StatusCode != 413 {
		t.Fatalf("oversize upload should be 413, got %d", resp.StatusCode)
	}
	entries, _ := os.ReadDir(e.store.FilesDir())
	if len(entries) != 0 {
		t.Fatalf("failed upload left %d files on disk", len(entries))
	}
	// non-admins cannot upload
	e.mkUser("emp", "EmployeePass1", RoleEmployee)
	if resp, _ := e.upload(e.login("emp", "EmployeePass1"), "PUBLIC", "x", []byte("x"), true); resp.StatusCode != 403 {
		t.Fatalf("employee upload should be 403, got %d", resp.StatusCode)
	}
}

func TestTamperedFileOnDiskIsRefused(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	id := e.mkFile(adm, "PUBLIC", "p.txt", []byte("hello world"))
	e.grant(adm, id, RoleAdmin, ActionDownload)
	f, _ := e.store.FileByID(id)
	raw, _ := os.ReadFile(f.EncPath)
	raw[len(raw)-1] ^= 1
	os.WriteFile(f.EncPath, raw, 0o600)
	resp, body := e.access(adm, id, ActionDownload)
	if resp.StatusCode != 500 || bytes.Contains(body, []byte("hello")) {
		t.Fatalf("tampered file must not be served: %d %s", resp.StatusCode, body)
	}
	if e.auditActions()["INTEGRITY_FAILURE/DENY"] == 0 {
		t.Fatal("integrity failure not audited")
	}
}

// ---------- Sessions ----------
func TestLogoutInvalidatesToken(t *testing.T) {
	e := setup(t)
	tok := e.login("admin", "AdminPass123")
	if resp, _ := e.req("GET", "/api/me", tok, nil); resp.StatusCode != 200 {
		t.Fatal("me failed")
	}
	if resp, _ := e.req("POST", "/api/logout", tok, nil); resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if resp, _ := e.req("GET", "/api/me", tok, nil); resp.StatusCode != 401 {
		t.Fatalf("token must be dead after logout, got %d", resp.StatusCode)
	}
}

// ---------- Passwords ----------
func TestLegacyHashUpgradedOnLogin(t *testing.T) {
	e := setup(t)
	salt := "c2FsdHNhbHRzYWx0"
	sum := sha256.Sum256([]byte(salt + ":" + "OldPass123"))
	u := &User{ID: newID("user"), Username: "olduser", PasswordHash: base64.StdEncoding.EncodeToString(sum[:]), Salt: salt, Role: RoleEmployee, CreatedAt: time.Now()}
	if err := e.store.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	e.login("olduser", "OldPass123")
	after, _ := e.store.UserByUsername("olduser")
	if after.Salt != "" || !strings.HasPrefix(after.PasswordHash, "$2") {
		t.Fatalf("hash not upgraded to bcrypt: salt=%q hash=%q", after.Salt, after.PasswordHash[:4])
	}
	e.login("olduser", "OldPass123") // still works afterwards
}

// ---------- MFA ----------
func enrolMFA(t *testing.T, e *env, tok string) (secret string, recovery []string) {
	t.Helper()
	resp, body := e.req("POST", "/api/mfa/setup", tok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("setup: %d %s", resp.StatusCode, body)
	}
	var s struct{ Secret, OtpauthUri string }
	json.Unmarshal(body, &s)
	if !strings.HasPrefix(s.OtpauthUri, "otpauth://totp/") {
		t.Fatal("bad otpauth uri")
	}
	if resp, _ := e.req("POST", "/api/mfa/enable", tok, map[string]string{"code": "000000"}); resp.StatusCode != 401 {
		t.Fatalf("wrong code must not enable MFA, got %d", resp.StatusCode)
	}
	code, _ := TOTPAt(s.Secret, time.Now())
	resp, body = e.req("POST", "/api/mfa/enable", tok, map[string]string{"code": code})
	if resp.StatusCode != 200 {
		t.Fatalf("enable: %d %s", resp.StatusCode, body)
	}
	var en struct{ RecoveryCodes []string }
	json.Unmarshal(body, &en)
	if len(en.RecoveryCodes) != 8 {
		t.Fatalf("want 8 recovery codes, got %d", len(en.RecoveryCodes))
	}
	return s.Secret, en.RecoveryCodes
}

func TestMFAFullFlow(t *testing.T) {
	e := setup(t)
	e.mkUser("mgr", "ManagerPass123", RoleHRManager)
	tok := e.login("mgr", "ManagerPass123")
	secret, recovery := enrolMFA(t, e, tok)

	// secret is encrypted at rest, never plaintext
	var enc string
	e.pool.QueryRow(context.Background(), `SELECT mfa_secret_enc FROM users WHERE username='mgr'`).Scan(&enc)
	if enc == "" || strings.Contains(enc, secret) {
		t.Fatal("TOTP secret must be stored encrypted")
	}
	// /api/me must not expose it
	_, me := e.req("GET", "/api/me", tok, nil)
	if strings.Contains(string(me), secret) || strings.Contains(string(me), "mfaSecret") {
		t.Fatal("secret leaked via /api/me")
	}

	// password alone no longer yields a session
	resp, body := e.req("POST", "/api/login", "", map[string]string{"username": "mgr", "password": "ManagerPass123"})
	var ch struct {
		MFARequired bool   `json:"mfaRequired"`
		MFAToken    string `json:"mfaToken"`
		Token       string `json:"token"`
	}
	json.Unmarshal(body, &ch)
	if resp.StatusCode != 200 || !ch.MFARequired || ch.Token != "" || ch.MFAToken == "" {
		t.Fatalf("expected MFA challenge, got %s", body)
	}
	// challenge token is not a session
	if resp, _ := e.req("GET", "/api/me", ch.MFAToken, nil); resp.StatusCode != 401 {
		t.Fatal("pending token must not authenticate API calls")
	}
	// wrong code
	if resp, _ := e.req("POST", "/api/login/mfa", "", map[string]string{"mfaToken": ch.MFAToken, "code": "123456"}); resp.StatusCode != 401 {
		t.Fatalf("wrong code: %d", resp.StatusCode)
	}
	// right code (use a code for a *future* step so it is newer than the one used at enrolment)
	code, _ := TOTPAt(secret, time.Now().Add(30*time.Second))
	resp, body = e.req("POST", "/api/login/mfa", "", map[string]string{"mfaToken": ch.MFAToken, "code": code})
	var ok struct{ Token string }
	json.Unmarshal(body, &ok)
	if resp.StatusCode != 200 || ok.Token == "" {
		t.Fatalf("valid code rejected: %d %s", resp.StatusCode, body)
	}
	if _, me := e.req("GET", "/api/me", ok.Token, nil); !strings.Contains(string(me), `"mfaVerified":true`) {
		t.Fatalf("session should be MFA verified: %s", me)
	}
	// replay: same code again in a fresh challenge is refused
	_, body = e.req("POST", "/api/login", "", map[string]string{"username": "mgr", "password": "ManagerPass123"})
	json.Unmarshal(body, &ch)
	if resp, _ := e.req("POST", "/api/login/mfa", "", map[string]string{"mfaToken": ch.MFAToken, "code": code}); resp.StatusCode != 401 {
		t.Fatalf("replayed TOTP must be rejected, got %d", resp.StatusCode)
	}
	// recovery code: works exactly once
	if resp, _ := e.req("POST", "/api/login/mfa", "", map[string]string{"mfaToken": ch.MFAToken, "code": recovery[0]}); resp.StatusCode != 200 {
		t.Fatalf("recovery code rejected: %d", resp.StatusCode)
	}
	_, body = e.req("POST", "/api/login", "", map[string]string{"username": "mgr", "password": "ManagerPass123"})
	json.Unmarshal(body, &ch)
	if resp, _ := e.req("POST", "/api/login/mfa", "", map[string]string{"mfaToken": ch.MFAToken, "code": recovery[0]}); resp.StatusCode != 401 {
		t.Fatalf("recovery code reuse must fail, got %d", resp.StatusCode)
	}
	got := e.auditActions()
	for _, w := range []string{"MFA_SETUP/ALLOW", "MFA_ENABLE/ALLOW", "MFA_ENABLE/DENY", "MFA_VERIFY/ALLOW", "MFA_VERIFY/DENY"} {
		if got[w] == 0 {
			t.Errorf("missing audit event %s", w)
		}
	}
}

func TestMFAChallengeBruteForceBlocked(t *testing.T) {
	e := setup(t)
	e.mkUser("mgr", "ManagerPass123", RoleHRManager)
	secret, _ := enrolMFA(t, e, e.login("mgr", "ManagerPass123"))
	_, body := e.req("POST", "/api/login", "", map[string]string{"username": "mgr", "password": "ManagerPass123"})
	var ch struct{ MFAToken string }
	json.Unmarshal(body, &ch)
	for i := 0; i < 5; i++ {
		e.req("POST", "/api/login/mfa", "", map[string]string{"mfaToken": ch.MFAToken, "code": "111111"})
	}
	good, _ := TOTPAt(secret, time.Now().Add(60*time.Second))
	resp, _ := e.req("POST", "/api/login/mfa", "", map[string]string{"mfaToken": ch.MFAToken, "code": good})
	if resp.StatusCode == 200 {
		t.Fatal("correct code accepted after 5 wrong guesses — brute force possible")
	}
}

func TestStepUpMFAForHighlyConfidential(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	e.mkUser("mgr", "ManagerPass123", RoleHRManager)
	id := e.mkFile(adm, "HIGHLY_CONFIDENTIAL", "board.txt", []byte("BOARD-MINUTES"))
	e.grant(adm, id, RoleHRManager, ActionRead, ActionDownload)

	tok := e.login("mgr", "ManagerPass123") // password-only session
	resp, body := e.access(tok, id, ActionRead)
	if resp.StatusCode != 403 || !strings.Contains(string(body), "multi-factor") {
		t.Fatalf("HC without MFA must be denied: %d %s", resp.StatusCode, body)
	}
	// enrolling MFA upgrades this very session
	enrolMFA(t, e, tok)
	resp, body = e.access(tok, id, ActionRead)
	if resp.StatusCode != 200 || string(body) != "BOARD-MINUTES" {
		t.Fatalf("HC with MFA session + policy must be allowed: %d %s", resp.StatusCode, body)
	}
}

func TestRequireMFAConfinesUnenrolledUsers(t *testing.T) {
	e := setup(t, func(c *Config) { c.RequireMFA = true })
	tok := e.login("admin", "AdminPass123")
	resp, body := e.req("GET", "/api/files", tok, nil)
	if resp.StatusCode != 403 || !strings.Contains(string(body), "mfaSetupRequired") {
		t.Fatalf("unenrolled user must be confined: %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.req("GET", "/api/me", tok, nil); resp.StatusCode != 200 {
		t.Fatal("/api/me must stay reachable")
	}
	enrolMFA(t, e, tok)
	if resp, _ := e.req("GET", "/api/files", tok, nil); resp.StatusCode != 200 {
		t.Fatalf("after enrolment the vault must be usable, got %d", resp.StatusCode)
	}
	if resp, _ := e.req("POST", "/api/mfa/disable", tok, map[string]string{"password": "AdminPass123", "code": "123456"}); resp.StatusCode != 403 {
		t.Fatal("MFA must not be disable-able when mandatory")
	}
}

func TestMFADisableAndAdminReset(t *testing.T) {
	e := setup(t)
	adm := e.login("admin", "AdminPass123")
	u := e.mkUser("carol", "CarolPass1234", RoleHR)
	tok := e.login("carol", "CarolPass1234")
	secret, _ := enrolMFA(t, e, tok)

	// wrong password -> refuse
	code, _ := TOTPAt(secret, time.Now().Add(30*time.Second))
	if resp, _ := e.req("POST", "/api/mfa/disable", tok, map[string]string{"password": "nope", "code": code}); resp.StatusCode != 401 {
		t.Fatalf("disable with wrong password: %d", resp.StatusCode)
	}
	// admin reset: carol locked out of her device -> reset, sessions revoked
	if resp, _ := e.req("POST", "/api/users/"+u.ID+"/mfa/reset", adm, nil); resp.StatusCode != 200 {
		t.Fatalf("admin reset failed: %d", resp.StatusCode)
	}
	if resp, _ := e.req("GET", "/api/me", tok, nil); resp.StatusCode != 401 {
		t.Fatal("reset must revoke the user's sessions")
	}
	e.login("carol", "CarolPass1234") // password-only again
	// non-admin cannot reset
	if resp, _ := e.req("POST", "/api/users/"+u.ID+"/mfa/reset", e.login("carol", "CarolPass1234"), nil); resp.StatusCode != 403 {
		t.Fatal("non-admin MFA reset must be forbidden")
	}
	if e.auditActions()["MFA_RESET/ALLOW"] == 0 {
		t.Fatal("reset not audited")
	}
	_ = url.QueryEscape
}
