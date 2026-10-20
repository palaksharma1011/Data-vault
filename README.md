# Data-Centric Zero-Trust Secure Data Vault — Version 1

A working implementation of the narrowed Version 1 scope: encrypted file
storage, data classification, a Zero-Trust policy engine, and security
audit logging, with an admin dashboard and a role-based access UI.

This is real, runnable code — not a mockup. It has been built and
exercised end-to-end (the exact scenario from Section 8 of the scope
document) before being handed to you. See `DOCUMENTATION.md` for how
every objective in the scope maps to the code.

## What's here

```
vault/
├── README.md              ← you are here
├── DOCUMENTATION.md        ← scope-to-implementation mapping, architecture, design notes
├── docker-compose.yml
└── backend/
    ├── main.go             ← entry point, routing, first-run bootstrap
    ├── models.go           ← User / FileResource / Policy / AuditEntry
    ├── store.go             ← PostgreSQL persistence (schema auto-created, audit log append-only)
    ├── crypto.go            ← streaming chunked AES-256-GCM (with AAD), key management, bcrypt
    ├── auth.go               ← sessions (idle + absolute expiry, cleanup), auth middleware
    ├── policy.go             ← the Zero-Trust policy engine (clearance, MFA step-up, no admin bypass)
    ├── audit.go              ← hash-chained, tamper-evident audit logging (fails closed)
    ├── totp.go / mfa.go      ← TOTP (RFC 6238) + recovery codes, MFA endpoints
    ├── ratelimit.go          ← login / MFA brute-force lockout
    ├── handlers.go           ← HTTP handlers wiring everything together
    ├── *_test.go             ← unit + end-to-end tests (see "Tests" below)
    ├── Dockerfile
    ├── go.mod                ← deps: pgx (PostgreSQL driver), x/crypto (bcrypt)
    └── web/                  ← reference dashboard UI (served by the Go binary)
        ├── index.html
        ├── style.css
        └── app.js
```

The backend needs PostgreSQL. It has two Go dependencies (`pgx`,
`golang.org/x/crypto`); run `go mod tidy` once to fetch them and write
`go.sum`. The UI is plain HTML/CSS/JS with no `npm install` step.
Also in the repo: `VERIFYING_FIXES.md` (how to check each security fix)
and `scripts/verify-fixes.sh` (automated black-box check).

## Running it

### Option A — plain Go (fastest for a demo)

Requires Go 1.22+.

```bash
# needs a running Postgres and DATABASE_URL set (or use Option B)
cd backend
go mod tidy
go run .
```

The server starts on `http://localhost:8080` and prints a default
administrator account to the console on first run:

```
username: admin
password: Admin@123
```

Open `http://localhost:8080` in a browser and sign in.

### Option B — Docker

```bash
docker compose up --build
```

Same thing, containerized, matching the scope's "Deployment: Docker"
row. Data persists in the `vault-data` volume.

### Configuration (optional environment variables)

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://vault:vault@localhost:5432/vault?sslmode=disable` |
| `VAULT_ADDR` | listen address | `:8080` |
| `VAULT_DATA_DIR` | where encrypted files, metadata and the master key are stored | `./data` |
| `VAULT_REQUIRE_MFA` | `true` forces every user to enrol MFA before using the vault, and forbids disabling it | `false` |
| `VAULT_HIDE_UNAUTHORIZED` | `true` makes file lists show non-admins only files their role has a policy for | `false` |
| `VAULT_MAX_UPLOAD_MB` | maximum upload size | `200` |
| `VAULT_ADMIN_PASSWORD` | initial password for the bootstrap `admin` (first run only) | `Admin@123` (demo) |
| `VAULT_TRUST_PROXY` | `true` = use `X-Forwarded-For` for per-IP rate limiting (only behind your own reverse proxy) | `false` |
| `VAULT_MFA_ISSUER` | name shown in the authenticator app | `Zero-Trust Vault` |
| `VAULT_MASTER_KEY` | base64-encoded 32-byte key-encryption key; if unset, one is generated and persisted under `VAULT_DATA_DIR/master.key` | (generated) |

## Demo script (matches Section 8 of the scope document)

This is the exact walkthrough to run in front of your supervisor.

1. **Log in as `admin` / `Admin@123`.**
2. Go to **Users** → create `hr_alice` (role `HR`), `mgr_bob` (role
   `HR_MANAGER`), `emp_carol` (role `EMPLOYEE`).
3. Go to **Files & Policies** → upload `employee_salary.xlsx`, classify
   it **CONFIDENTIAL**. Watch the file appear — the app has already
   AES-256-GCM-encrypted it before writing it to disk (you can `xxd`
   the file under `data/files/*.enc` to show your supervisor it's
   unreadable binary, not the original spreadsheet).
4. Still on **Files & Policies**, click **+ Policy** on the file:
   - Grant `HR` → `READ`
   - Grant `HR_MANAGER` → `READ` + `DOWNLOAD`
   - (leave `EMPLOYEE` with no policy at all — this is the point)
   > Passwords must be at least 10 characters with a letter and a digit
   > (e.g. `HrAlice12345`). Policies can only grant a role access within its
   > clearance: EMPLOYEE ≤ INTERNAL, HR ≤ CONFIDENTIAL, HR_MANAGER/ADMIN ≤ HIGHLY_CONFIDENTIAL.
5. Log out, log in as `emp_carol`, go to **My Access**, click
   **Download** on the file → **DENY**, with an explicit reason
   ("no policy entry... DENY by default").
6. Log out, log in as `mgr_bob`, click **Download** → **ALLOW**, file
   decrypts and downloads.
7. Log out, log in as `hr_alice`, click **Download** → **DENY**
   (policy only grants READ); click **Read** → **ALLOW**, previewed
   inline.
8. Log back in as `admin`, open **Dashboard** and **Audit Log** → show
   every one of the above attempts recorded with user, role, resource,
   action, decision and reason — including the denied ones.

9. **MFA bonus:** log in as `mgr_bob`, open **Security**, set up an
   authenticator app, confirm, save the recovery codes. Log out and in
   again — you now need the 6-digit code. Upload a `HIGHLY_CONFIDENTIAL`
   file as admin, grant `HR_MANAGER → READ`, and see that `mgr_bob` is
   only allowed in an MFA-verified session.

This demonstrates the central claim of Version 1: **a successful login
never implies access** — every request is evaluated against identity,
role, classification and policy, with an explicit, logged decision.

## Tests

```bash
cd backend
go test ./...                      # unit tests (crypto, TOTP, policy, audit chain, limiter, sessions)
# plus end-to-end tests against a real PostgreSQL (WIPES that database's public schema!):
TEST_DATABASE_URL='postgres://vault:vault@localhost:5432/vault_test?sslmode=disable' go test -race ./...
```

Against a running server: `./scripts/verify-fixes.sh`. Details of every check are in `VERIFYING_FIXES.md`.

## Notes for your supervisor discussion

- Passwords use bcrypt (cost 12). Accounts created by the old salted-SHA-256 build still log in once and are upgraded automatically.
- Persistence is PostgreSQL. Encrypted file blobs stay on disk (`data/files`); metadata, users, policies and the audit log are in the database.
- There is **no administrator bypass**: ADMIN is evaluated like every role and needs an explicit policy. Administrators still manage users, policies and the audit log.
- The reference UI is vanilla HTML/CSS/JS (no build step) and talks to the same REST API a React frontend would.
- See `VERIFYING_FIXES.md` §"Known limitations" for what is deliberately not done.
