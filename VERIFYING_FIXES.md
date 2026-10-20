# Verifying the security fixes and MFA

Three ways to check, from fastest to most thorough:

| Way | Command | What it proves |
| --- | --- | --- |
| Automated, running server | `./scripts/verify-fixes.sh` | Black-box check of every fix below with `curl` (needs a fresh instance with admin password `Admin@123`, or `ADMIN_PW=...`) |
| Automated, code level | `cd backend && TEST_DATABASE_URL='postgres://vault:vault@localhost:5432/vault_test?sslmode=disable' go test -race ./...` | 46 unit + end-to-end tests (wipes that test database) |
| By hand | the sections below | You see each behaviour yourself |

Handy commands (Docker setup): `docker compose exec postgres psql -U vault -d vault` opens SQL; the app is at http://localhost:8080.

---

## The six confirmed problems

### 1. Classification was ignored → now enforced (`policy.go`)
**What changed:** every role has a *clearance* (EMPLOYEE ≤ INTERNAL, HR ≤ CONFIDENTIAL, HR_MANAGER and ADMIN ≤ HIGHLY_CONFIDENTIAL). A policy can only grant access *within* it. Policy creation also refuses impossible grants, and the engine re-checks at access time. HIGHLY_CONFIDENTIAL additionally needs an MFA-verified session.

**Check (UI):** as admin upload a file as `HIGHLY_CONFIDENTIAL`, click **+ Policy**, choose `EMPLOYEE` + `DOWNLOAD`, **Save** → error *"role EMPLOYEE is not cleared for HIGHLY_CONFIDENTIAL data…"*.

**Check the engine itself (bypass the API check):** insert the bad policy straight into the database, then try as the employee:
```sql
INSERT INTO policies (id, resource_id, role, actions, created_at)
VALUES ('p_manual', '<FILE_ID>', 'EMPLOYEE', '{DOWNLOAD}', now());
```
Employee clicks **Download** → **DENY** *"Role EMPLOYEE is not cleared for HIGHLY_CONFIDENTIAL data … regardless of any policy"*. (Get `<FILE_ID>` with `SELECT id, name FROM files;`.)

### 2. DELETE returned the file's contents → now deletes and returns nothing
**What changed:** `READ` = 64 KiB preview, `DOWNLOAD` = whole file, `DELETE` = removes the DB row, its policies and the encrypted file; the response is `{"deleted":true}` with no content. Deleted files are gone for good.

**Check:** upload an `INTERNAL` file, grant `EMPLOYEE → DELETE`, log in as the employee, press **Delete**. You get "Deleted: …" (no data), the file disappears from the list, and `ls data/files` (or the `vault-data` volume) no longer has its `.enc`. A second delete → 404.

### 3. File list leaked path, nonce, wrapped key → removed
**What changed:** `GET /api/files` returns only `id, name, classification, size, uploadedAt` (a `FileView`). Storage fields are never serialised anywhere. Optional hardening: `VAULT_HIDE_UNAUTHORIZED=true` also hides files a role has no policy for.

**Check:**
```bash
TOKEN=...   # from POST /api/login
curl -s localhost:8080/api/files -H "Authorization: Bearer $TOKEN"
```
No `encPath`, `nonce`, `wrappedKey`, `ownerId`.

### 4. Policy creation accepted garbage → validated
**What changed:** role, actions, resource, classification-vs-clearance are validated (400); duplicate role+resource is 409; unknown policy id on delete is 404. Users: username pattern, role, password strength (≥10 chars, letter + digit).

**Check:**
```bash
curl -s -X POST localhost:8080/api/policies -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"resourceId":"<FILE_ID>","role":"BANANA","actions":["FLY"]}'   # → 400
```

### 5. No login protection → lockout
**What changed (`ratelimit.go`):** 5 failed attempts per username (or 20 per IP) inside 15 min → locked 15 min, doubling on repeat up to 1 h; HTTP **429** with `Retry-After`. Applies equally to unknown usernames (no enumeration), to MFA codes, and a locked account rejects even the correct password. Passwords are checked in constant-ish time for unknown users too.

**Check:** try a wrong password 6 times in the UI → *"too many failed attempts — try again later"*; then try the right one → still refused.

### 6. Audit covered only file access → now every security event
**What changed:** logged: login success/failure, lockouts, MFA verify/setup/enable/disable/reset, logout, user creation, upload, policy create/revoke, delete, integrity failures, plus every access decision.
- **Fail-closed:** `LogAudit` returns its error; if the audit write fails the request is refused (no data released, nothing deleted).
- **Tamper-evident:** each entry stores `hash = SHA256(prev_hash ‖ fields)`. `GET /api/audit/verify` (or **Audit Log → Verify log integrity**) re-checks the chain.
- **Append-only:** database triggers reject `UPDATE`, `DELETE`, `TRUNCATE` on `audit_log`.
- **Scalable:** it's a PostgreSQL table now (no whole-file rewrites); lists are paged (`?limit=&offset=`).

**Check coverage:** do a few things (wrong login, create user, upload, grant policy), then open **Audit Log**.

**Check immutability:**
```sql
UPDATE audit_log SET reason = 'x';     -- ERROR: audit_log is append-only (UPDATE not allowed)
DELETE FROM audit_log;                 -- ERROR ... (DELETE not allowed)
```
**Check tamper detection** (simulates a DBA who disables the trigger):
```sql
ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update;
UPDATE audit_log SET decision = 'ALLOW' WHERE seq = 3;
```
Press **Verify log integrity** → red banner naming the first bad entry. (The chain stays broken afterwards on purpose; reset with `docker compose down -v`.)

**Check fail-closed:**
```sql
ALTER TABLE audit_log RENAME TO audit_log_off;
```
Now any file Read/Download returns *"audit trail unavailable — request refused"* and no data. Restore with `ALTER TABLE audit_log_off RENAME TO audit_log;`.

---

## The smaller issues

| Issue | Fix | Check |
| --- | --- | --- |
| Salted SHA-256 passwords | **bcrypt** (cost 12). Old hashes still work once and are upgraded on login | `SELECT username, left(password_hash,4) FROM users;` → `$2a$` |
| Admin bypass | Removed. ADMIN needs a policy like everyone (still manages users/policies/audit) | As admin press **Read** on a file with no ADMIN policy → DENY; add a policy for role `ADMIN` → ALLOW |
| Hidden audit failures | Fail closed (see #6) | the RENAME test above |
| Audit tampering / rewrite-per-event | Hash chain + triggers + PostgreSQL | #6 |
| No AAD binding | Chunk AAD = file id + classification; DEK wrap bound to file id; MFA secret bound to user id | `go test -run AAD` (relabelling a file's classification in the DB makes decryption fail) |
| Whole files in RAM / 15 s write timeout | Streaming chunked encryption (constant memory); upload straight into encryption (no temp plaintext file); per-request 30-min deadlines; `VAULT_MAX_UPLOAD_MB` limit (413) | `head -c 150M /dev/urandom > big.bin`, upload it, download it, `sha256sum` both; watch `docker stats` stay flat |
| No logout / no session cleanup | `POST /api/logout`; 30-min idle + 12-h absolute expiry; janitor removes expired sessions every minute; tokens are stored hashed | Log out, then reuse the token → 401 |
| No tests | `*_test.go` (see top) | `go test ./...` |
| Broken `docs/postgres_migration.md` comment | Removed with the rewrite of `store.go` | — |

---

## Multi-factor authentication (TOTP)

**How it works**
1. **Enrol** (Security tab): *Set up authenticator app* shows a setup key (and an `otpauth://` link). Add it to Google/Microsoft Authenticator, Authy, 1Password… as a *time-based* account, type the 6-digit code to confirm → MFA is on and you receive **8 one-time recovery codes** (shown once).
2. **Sign in:** password → `{mfaRequired, mfaToken}` (a 5-minute challenge that grants nothing) → `POST /api/login/mfa` with a TOTP code or a recovery code → session. Five wrong codes burn the challenge and lock the account for 15 min.
3. **Step-up:** HIGHLY_CONFIDENTIAL (any action) and DELETE on CONFIDENTIAL are denied unless the session passed MFA.
4. **Replay protection:** a code's 30-second time step is recorded; reusing a code (or an older one) is refused.
5. **At rest:** the secret is AES-256-GCM-encrypted with the master key (bound to the user id); recovery codes are stored as SHA-256 hashes and are single-use.
6. **Recovery:** a recovery code, or an administrator using **Users → Reset MFA** (audited, revokes that user's sessions).
7. **Mandatory mode:** `VAULT_REQUIRE_MFA=true` confines any un-enrolled user to the Security tab until they enrol and forbids disabling MFA.

**Check by hand**
1. Log in as `admin`, **Security → Set up authenticator app**, confirm, save codes.
2. Log out, log in: after the password you're asked for a code. A wrong code is refused; the right one works.
3. Re-submit the *same* code in a new login within 30 s → refused (replay).
4. Log in with a recovery code → works once; the same code again → refused.
5. As admin upload a `HIGHLY_CONFIDENTIAL` file, grant `HR_MANAGER → READ`. As an `HR_MANAGER` **without** MFA press Read → DENY "requires … multi-factor". Enrol MFA (the same session upgrades) → ALLOW.
6. `SELECT mfa_enabled, mfa_secret_enc FROM users;` → the secret is ciphertext, not base32.

**Generating a code from a terminal** (no phone), given the setup key:
```bash
python3 - <<'PY'
import hmac, hashlib, struct, time, base64
key = input("setup key: ").replace(" ", "").upper()
key += "=" * (-len(key) % 8)
k = base64.b32decode(key)
h = hmac.new(k, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
o = h[-1] & 15
print("%06d" % ((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 10**6))
PY
```

---

## Known limitations (so nothing surprises you)

- **No QR code** on the MFA screen — you enter the setup key manually (every authenticator app supports this).
- **Sessions and lockout counters live in memory:** a restart logs everyone out and clears lockouts; with several replicas each has its own counters.
- **Username lockout can be abused to lock a victim out** for 15 min (the usual trade-off; the per-IP limit and admin visibility in the audit log mitigate it).
- **An admin can grant themselves a policy.** It is audited, but there is no second-person approval ("four eyes").
- **Audit chain is not anchored outside the database:** someone with full database rights who recomputes the entire chain could rewrite history undetected. Periodically record `headHash` (shown by *Verify*) somewhere separate to close that gap.
- **Encrypted blobs and `master.key` are on the same disk;** use `VAULT_MASTER_KEY` from a secret manager or a real KMS for production.
- The bootstrap admin password defaults to the demo value `Admin@123` unless `VAULT_ADMIN_PASSWORD` is set — change it and enrol MFA at first login. There is no change-password endpoint yet.
- TOTP uses SHA-1 (the RFC default and what authenticator apps expect).
- `go.sum` is not included; `go mod tidy` (the Dockerfile runs it) creates it.
