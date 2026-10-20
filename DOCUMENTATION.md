# Documentation — Data-Centric Zero-Trust Secure Data Vault (Version 1)

## 1. What was built, and why it stops here

The scope document sets the boundary for Version 1 at Section 3
("Core Objectives") and Section 12 ("Final Scope Freeze"). Everything
in that Must-Have list has been implemented and tested end-to-end.
Everything in the Future Work list has been deliberately left out, not
started partway, so the boundary between "done" and "deferred" stays
clean and easy to explain in a viva.

This document exists so you (and your supervisor) can check that claim
line by line.

## 2. Scope objective → implementation mapping

| Scope objective (Section 3) | Where it lives | Status |
| --- | --- | --- |
| Authentication & Roles | `auth.go` (sessions), `handlers.go` (`handleLogin`, `handleLoginMFA`, `handleLogout`), `models.go` (`Role`), bcrypt in `crypto.go`, brute-force lockout in `ratelimit.go` | ✅ Done |
| Multi-factor authentication | `totp.go` (RFC 6238 TOTP, recovery codes), `mfa.go` (setup / enable / disable / admin reset), step-up rule in `policy.go` | ✅ Done |
| Data Classification | `models.go` (`Classification`: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `HIGHLY_CONFIDENTIAL`), enforced at upload in `handleUploadFile` | ✅ Done |
| Secure Storage (AES-256-GCM) | `crypto.go` (`EncryptStream`/`OpenFile`: chunked, streaming, AAD-bound), files never written to disk unencrypted | ✅ Done |
| Policy Management | `handlers.go` (`handleCreatePolicy`, `handleListPolicies`, `handleDeletePolicy`), admin-only | ✅ Done |
| Zero-Trust Authorization | `policy.go` (`EvaluateAccess`) — the core of the project | ✅ Done |
| Audit Logging | `audit.go` (`LogAudit`, hash chain, `VerifyAuditChain`), `store.go` (append-only table + triggers); covers logins, MFA, uploads, user/policy changes and every access decision | ✅ Done |
| Administrative Dashboard | `web/` UI, `handlers.go` (`handleDashboardSummary`, `handleListAudit`) | ✅ Done |

MFA was originally deferred and is now implemented (TOTP). The rest of Section 4 / Section 12's "Future Work" list (device
trust, DLP, behavioural risk scoring, key rotation/KMS, Redis,
NATS, OPA, MinIO/S3, Prometheus/Grafana, distributed deployment) is
untouched, exactly as the scope document specifies. Nothing has been
half-built in that direction.

## 3. Architecture

```
Browser (reference UI, web/)
        │  HTTPS/HTTP, JSON + multipart
        ▼
Go HTTP API (main.go / handlers.go)
        │
        ├── auth.go      → session validation, role guard
        ├── policy.go    → EvaluateAccess(user, resource, action) → ALLOW/DENY + reason
        ├── crypto.go     → AES-256-GCM encrypt/decrypt, key wrapping
        ├── audit.go      → append-only audit trail
        └── store.go      → repository (Users, Files, Policies, Audit)
                    │
                    ▼
        PostgreSQL (users, files, policies, audit_log)  +  data/files/<id>.enc  +  data/master.key
```

This matches the scope's Section 6 flow —
**Frontend → API → Identity/Policy/Audit → Data Vault → storage** —
with PostgreSQL and local protected storage both currently represented
by the `store.go` repository and the `data/` directory (see §6, Future
Work note, for exactly how to swap in real PostgreSQL later).

## 4. The policy engine (Section 7 of the scope) — how it actually decides

`policy.go`'s `EvaluateAccess` is the one function that matters most in
a viva. Its rule order, in plain terms:

1. **Unknown action or classification → DENY.**
2. **Role clearance below the file's classification → DENY**, whatever
   any policy says (EMPLOYEE ≤ INTERNAL, HR ≤ CONFIDENTIAL,
   HR_MANAGER and ADMIN ≤ HIGHLY_CONFIDENTIAL). Policies can only grant
   access *within* a role's clearance.
3. **Classification demands MFA and the session has none → DENY.**
   HIGHLY_CONFIDENTIAL needs an MFA-verified session for every action;
   DELETE on CONFIDENTIAL needs one too.
4. **No policy for this resource, no policy for this role, or the policy
   lacks the action → DENY**, with a reason naming what *is* permitted.
5. **Otherwise ALLOW.**

There is **no administrator override**: ADMIN is evaluated by exactly
the same rules and needs an explicit policy (creating it is itself an
audited event).

Every path returns a decision *and* a reason, and the decision is
written to the audit log **before** any data is released or deleted
(`handleAccessFile`). If the audit write fails the request is refused
(fail closed). Actions: `READ` returns a 64 KiB decrypted preview,
`DOWNLOAD` the whole file, `DELETE` removes the file and returns no data.

This is a direct implementation of the worked example in the scope
document (Section 7): `employee_salary.xlsx`, classified
`CONFIDENTIAL`, with `HR → READ`, `HR_MANAGER → READ+DOWNLOAD`, no
entry for `EMPLOYEE`. The automated test run below reproduces that
example exactly, including the wording of the DENY reason.

## 5. Encryption design (Section 9 of the scope)

- Every uploaded file gets its own random 256-bit **Data Encryption
  Key (DEK)** (`crypto.go`, `NewDEK`).
- Files are sealed with **AES-256-GCM in 64 KiB chunks**
  (`EncryptStream`), so memory use is constant for any file size and
  plaintext is never written to disk (uploads are streamed straight into
  encryption). Each chunk's nonce is `prefix | counter | last-flag`, so
  reordering and truncation are detected, and every chunk is
  authenticated with **AAD = file id + classification**: moving a
  ciphertext to another record or relabelling its classification makes
  decryption fail. The wrapped DEK is bound to the file id as well.
- The DEK is **envelope-encrypted** by the master key (`Seal`/`Open`,
  AES-256-GCM). MFA secrets are protected the same way, bound to the user id.
- On download, plaintext of a chunk is released only after that chunk's
  tag verified; the first chunk is verified before any response header is sent.
- Files written by the previous (single-shot) format stay readable
  (`enc_version` 1) and new files use version 2.
- The `KeyManager` type is isolated so it can be replaced by a real KMS/HSM.

This was verified directly during testing: the encrypted file on disk
(`data/files/<id>.enc`) was confirmed to be opaque binary, not the
original spreadsheet content, before it was ever served back out
through an ALLOW decision.

## 6. Deliberate simplifications, and how to undo each one

These are documented so nothing here is mistaken for an oversight in
review.

| Simplification | Why, for V1 | How to move to production |
| --- | --- | --- |
| Encrypted file blobs live on local disk, not object storage | Simple and fast for one instance | Implement the same open/create calls against S3/MinIO; metadata is already in PostgreSQL. |
| Lockout counters and sessions are in process memory | Single-instance demo | Move them to Redis/PostgreSQL for multi-replica or restart-surviving state. |
| Sessions are an in-memory token map (`auth.go`), lost on restart | Simplest possible correct implementation for a single-instance demo | Move the map into the same store used for everything else (or a fast store like Redis, which is already on the Level 2/3 roadmap in the scope document) if the process needs to survive restarts or run as multiple replicas. |
| Reference UI is vanilla HTML/CSS/JS (`web/`), not React/Next.js | No `npm install`, no build step, opens instantly, but consumes the exact same JSON REST API | The API contract (`handlers.go`) is already framework-agnostic. A React/Next.js frontend can be built against the same endpoints listed in §7 below with no backend change. |
| Master key is a locally generated/stored file (`data/master.key`) unless `VAULT_MASTER_KEY` is set | Simplest correct key-management module per Section 9's explicit allowance ("does not need to implement the full enterprise-grade key rotation... planned for the larger platform") | Point `KeyManager` at a real KMS/HSM client for wrapping/unwrapping DEKs (Level 2 on the scope's roadmap). |

## 7. API reference

All endpoints except `/api/login` require `Authorization: Bearer <token>`.

| Method & Path | Role required | Purpose |
| --- | --- | --- |
| `POST /api/login` | — | `{username, password}` → `{token, user}` or `{mfaRequired, mfaToken}`; 429 when locked out |
| `POST /api/login/mfa` | — | `{mfaToken, code}` (TOTP or recovery code) → `{token, user}` |
| `POST /api/logout` | any | ends the session |
| `POST /api/mfa/setup` | any | start enrolment → `{secret, otpauthUri}` |
| `POST /api/mfa/enable` | any | `{code}` → activates MFA, returns 8 one-time recovery codes |
| `POST /api/mfa/disable` | any | `{password, code}` (blocked when `VAULT_REQUIRE_MFA=true`) |
| `POST /api/users/{id}/mfa/reset` | ADMIN | clear a user's MFA and revoke their sessions |
| `GET /api/audit/verify` | ADMIN | verify the audit hash chain |
| `GET /api/me` | any | current user |
| `POST /api/users` | ADMIN | create user `{username, password, role}` |
| `GET /api/users` | ADMIN | list users |
| `POST /api/files/upload` | ADMIN | multipart: `classification` **then** `file` (streamed, size-limited) |
| `GET /api/files` | any | `id, name, classification, size, uploadedAt` only |
| `POST /api/files/{id}/access` | any | `{action}` → 403 JSON on DENY; on ALLOW READ = 64 KiB preview, DOWNLOAD = full stream, DELETE = `{deleted:true}` |
| `POST /api/policies` | ADMIN | `{resourceId, role, actions: []}` |
| `GET /api/policies` | ADMIN | list all policies |
| `DELETE /api/policies/{id}` | ADMIN | revoke a policy |
| `GET /api/audit?limit=&offset=` | ADMIN | audit trail, newest first |
| `GET /api/dashboard/summary` | ADMIN | counts + recent events for the dashboard |

## 8. Verification performed before delivery

The exact Section 8 scenario was run against a live instance of this
code (not just read through) before this was handed over:

1. Created `hr_alice` (HR), `mgr_bob` (HR_MANAGER), `emp_carol`
   (EMPLOYEE) as the admin.
2. Uploaded and classified `employee_salary.xlsx` as `CONFIDENTIAL`.
3. Granted `HR → READ` and `HR_MANAGER → READ+DOWNLOAD`; left
   `EMPLOYEE` with no policy.
4. `emp_carol` → `DOWNLOAD` → **DENY**, reason: *"Role EMPLOYEE has no
   policy entry for resource … — DENY by default"*.
5. `mgr_bob` → `DOWNLOAD` → **ALLOW**, file decrypted correctly back to
   its original bytes.
6. `hr_alice` → `DOWNLOAD` → **DENY** (only READ granted); `hr_alice` →
   `READ` → **ALLOW**.
7. Confirmed the on-disk file under `data/files/*.enc` was opaque
   ciphertext, not the original content.
8. Confirmed all five events (2 allows-that-were-repeats, 1 deny, 1
   allow, 1 deny, 1 allow — five total attempts) appeared correctly in
   `/api/audit` with correct user, role, action, decision and reason,
   and that `/api/dashboard/summary`'s allow/deny counts matched.

This is the same script written out step-by-step in `README.md`'s
"Demo script" section, so you can repeat it live for your supervisor.

## 9. Honest limitations to mention if asked

See `VERIFYING_FIXES.md` ("Known limitations") for the current list.
Summary: single instance; sessions and lockout counters are in memory;
no QR code in the MFA screen (manual key entry); an administrator can
grant themselves a policy (audited, but no second-person approval); the
audit chain is not anchored outside the database; the bootstrap admin
has a documented demo password unless `VAULT_ADMIN_PASSWORD` is set.
