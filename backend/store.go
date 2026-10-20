package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the persistence layer, backed by PostgreSQL (pgx connection
// pool). Public method signatures are unchanged from the JSON-file
// version, so handlers.go, policy.go, audit.go and auth.go need no edits.
//
// Encrypted file *contents* (AES-256-GCM ciphertext) still live on disk
// under dataDir/files; all metadata — users, files, policies, audit —
// lives in PostgreSQL.
type Store struct {
	pool    *pgxpool.Pool
	dataDir string
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            TEXT PRIMARY KEY,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	salt          TEXT NOT NULL DEFAULT '',
	role          TEXT NOT NULL,
	created_at    TIMESTAMPTZ NOT NULL
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_enc  TEXT    NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_step   BIGINT  NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_hashes TEXT[]  NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS files (
	id             TEXT PRIMARY KEY,
	name           TEXT NOT NULL,
	classification TEXT NOT NULL,
	owner_id       TEXT NOT NULL,
	enc_path       TEXT NOT NULL,
	nonce          TEXT NOT NULL DEFAULT '',
	wrapped_key    TEXT NOT NULL,
	size           BIGINT NOT NULL,
	uploaded_at    TIMESTAMPTZ NOT NULL
);
ALTER TABLE files ADD COLUMN IF NOT EXISTS enc_version INT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS policies (
	id          TEXT PRIMARY KEY,
	resource_id TEXT NOT NULL,
	role        TEXT NOT NULL,
	actions     TEXT[] NOT NULL,
	created_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policies_resource ON policies(resource_id);

CREATE TABLE IF NOT EXISTS audit_log (
	id          TEXT PRIMARY KEY,
	ts          TIMESTAMPTZ NOT NULL,
	user_id     TEXT NOT NULL,
	username    TEXT NOT NULL,
	role        TEXT NOT NULL,
	resource_id TEXT NOT NULL,
	resource    TEXT NOT NULL,
	action      TEXT NOT NULL,
	decision    TEXT NOT NULL,
	reason      TEXT NOT NULL
);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS seq       BIGSERIAL;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS hash      TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_log(seq DESC);

-- The audit log is append-only: the database itself refuses to change it.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
	RAISE EXCEPTION 'audit_log is append-only (% not allowed)', TG_OP;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
	FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
	FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();
`

// ErrConflict is returned when a unique constraint is violated.
var ErrConflict = errors.New("already exists")

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// NewStore connects to PostgreSQL using dsn, creates the schema if it does
// not exist, and prepares the directory for encrypted file blobs.
func NewStore(dataDir, dsn string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "files"), 0o700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var pool *pgxpool.Pool
	var err error
	// Retry: when started via docker compose, Postgres may still be booting.
	for attempt := 1; attempt <= 15; attempt++ {
		pool, err = pgxpool.New(ctx, dsn)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				break
			}
			pool.Close()
		}
		log.Printf("waiting for PostgreSQL (attempt %d/15): %v", attempt, err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// Best-effort unique indexes (may fail on legacy data containing duplicates;
	// the application also checks for duplicates itself).
	for _, stmt := range []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_resource_role ON policies(resource_id, role)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_user_username_ci ON users(lower(username))`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			log.Printf("warning: could not apply %q: %v", stmt, err)
		}
	}
	return &Store{pool: pool, dataDir: dataDir}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) FilesDir() string { return filepath.Join(s.dataDir, "files") }

func dbctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// --- Users ---

const userCols = `id, username, password_hash, salt, role, created_at, mfa_enabled, mfa_secret_enc, mfa_last_step, recovery_hashes`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	var role string
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &role, &u.CreatedAt,
		&u.MFAEnabled, &u.MFASecretEnc, &u.MFALastStep, &u.RecoveryHashes); err != nil {
		return nil, err
	}
	u.Role = Role(role)
	return &u, nil
}

func (s *Store) CreateUser(u *User) error {
	ctx, cancel := dbctx()
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (id, username, password_hash, salt, role, created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		u.ID, u.Username, u.PasswordHash, u.Salt, string(u.Role), u.CreatedAt)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) UserByUsername(username string) (*User, bool) {
	ctx, cancel := dbctx()
	defer cancel()
	u, err := scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE lower(username)=lower($1)`, username))
	if err != nil {
		if err != pgx.ErrNoRows {
			log.Printf("UserByUsername: %v", err)
		}
		return nil, false
	}
	return u, true
}

func (s *Store) UserByID(id string) (*User, bool) {
	ctx, cancel := dbctx()
	defer cancel()
	u, err := scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
	if err != nil {
		if err != pgx.ErrNoRows {
			log.Printf("UserByID: %v", err)
		}
		return nil, false
	}
	return u, true
}

func (s *Store) ListUsers() []*User {
	ctx, cancel := dbctx()
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at`)
	if err != nil {
		log.Printf("ListUsers: %v", err)
		return []*User{}
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			log.Printf("ListUsers scan: %v", err)
			continue
		}
		out = append(out, u)
	}
	return out
}

// UpdatePasswordHash upgrades a legacy SHA-256 hash to bcrypt (salt cleared).
func (s *Store) UpdatePasswordHash(id, hash string) error {
	ctx, cancel := dbctx()
	defer cancel()
	_, err := s.pool.Exec(ctx, `UPDATE users SET password_hash=$2, salt='' WHERE id=$1`, id, hash)
	return err
}

// --- MFA ---

// SetMFAPending stores a not-yet-confirmed (encrypted) TOTP secret.
func (s *Store) SetMFAPending(id, secretEnc string) error {
	ctx, cancel := dbctx()
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET mfa_secret_enc=$2, mfa_enabled=FALSE, mfa_last_step=0, recovery_hashes='{}' WHERE id=$1 AND mfa_enabled=FALSE`,
		id, secretEnc)
	return err
}

// EnableMFA switches MFA on and stores the recovery-code hashes.
func (s *Store) EnableMFA(id string, lastStep int64, recoveryHashes []string) error {
	ctx, cancel := dbctx()
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET mfa_enabled=TRUE, mfa_last_step=$2, recovery_hashes=$3 WHERE id=$1`,
		id, lastStep, recoveryHashes)
	return err
}

func (s *Store) DisableMFA(id string) error {
	ctx, cancel := dbctx()
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET mfa_enabled=FALSE, mfa_secret_enc='', mfa_last_step=0, recovery_hashes='{}' WHERE id=$1`, id)
	return err
}

// AdvanceMFAStep atomically records a used TOTP step; it returns false if
// that step (or a later one) was already used — i.e. a replayed code.
func (s *Store) AdvanceMFAStep(id string, step int64) (bool, error) {
	ctx, cancel := dbctx()
	defer cancel()
	tag, err := s.pool.Exec(ctx, `UPDATE users SET mfa_last_step=$2 WHERE id=$1 AND mfa_last_step < $2`, id, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ConsumeRecoveryCode atomically removes a recovery-code hash (single use).
func (s *Store) ConsumeRecoveryCode(id, hash string) (bool, error) {
	ctx, cancel := dbctx()
	defer cancel()
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET recovery_hashes = array_remove(recovery_hashes, $2) WHERE id=$1 AND $2 = ANY(recovery_hashes)`,
		id, hash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// --- Files ---

const fileCols = `id, name, classification, owner_id, enc_path, nonce, wrapped_key, size, uploaded_at, enc_version`

func scanFile(row pgx.Row) (*FileResource, error) {
	var f FileResource
	var class string
	if err := row.Scan(&f.ID, &f.Name, &class, &f.OwnerID, &f.EncPath, &f.Nonce, &f.WrappedKey, &f.Size, &f.UploadedAt, &f.EncVersion); err != nil {
		return nil, err
	}
	f.Classification = Classification(class)
	return &f, nil
}

func (s *Store) CreateFile(f *FileResource) error {
	ctx, cancel := dbctx()
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO files (`+fileCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		f.ID, f.Name, string(f.Classification), f.OwnerID, f.EncPath, f.Nonce, f.WrappedKey, f.Size, f.UploadedAt, f.EncVersion)
	return err
}

func (s *Store) FileByID(id string) (*FileResource, bool) {
	ctx, cancel := dbctx()
	defer cancel()
	f, err := scanFile(s.pool.QueryRow(ctx, `SELECT `+fileCols+` FROM files WHERE id=$1`, id))
	if err != nil {
		if err != pgx.ErrNoRows {
			log.Printf("FileByID: %v", err)
		}
		return nil, false
	}
	return f, true
}

func (s *Store) ListFiles() []*FileResource {
	ctx, cancel := dbctx()
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT `+fileCols+` FROM files ORDER BY uploaded_at DESC`)
	if err != nil {
		log.Printf("ListFiles: %v", err)
		return []*FileResource{}
	}
	defer rows.Close()
	out := []*FileResource{}
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			log.Printf("ListFiles scan: %v", err)
			continue
		}
		out = append(out, f)
	}
	return out
}

// DeleteFile removes a file's metadata and every policy attached to it,
// atomically. The caller removes the ciphertext from disk.
func (s *Store) DeleteFile(id string) error {
	ctx, cancel := dbctx()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM policies WHERE resource_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM files WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// --- Policies ---

const policyCols = `id, resource_id, role, actions, created_at`

func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	var role string
	var actions []string
	if err := row.Scan(&p.ID, &p.ResourceID, &role, &actions, &p.CreatedAt); err != nil {
		return nil, err
	}
	p.Role = Role(role)
	p.Actions = make([]Action, len(actions))
	for i, a := range actions {
		p.Actions[i] = Action(a)
	}
	return &p, nil
}

func (s *Store) CreatePolicy(p *Policy) error {
	actions := make([]string, len(p.Actions))
	for i, a := range p.Actions {
		actions[i] = string(a)
	}
	ctx, cancel := dbctx()
	defer cancel()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO policies (`+policyCols+`) VALUES ($1,$2,$3,$4,$5)`,
		p.ID, p.ResourceID, string(p.Role), actions, p.CreatedAt)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) PolicyByID(id string) (*Policy, bool) {
	ctx, cancel := dbctx()
	defer cancel()
	p, err := scanPolicy(s.pool.QueryRow(ctx, `SELECT `+policyCols+` FROM policies WHERE id=$1`, id))
	if err != nil {
		return nil, false
	}
	return p, true
}

func (s *Store) queryPolicies(query string, args ...any) []*Policy {
	ctx, cancel := dbctx()
	defer cancel()
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		log.Printf("queryPolicies: %v", err)
		return []*Policy{}
	}
	defer rows.Close()
	out := []*Policy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			log.Printf("queryPolicies scan: %v", err)
			continue
		}
		out = append(out, p)
	}
	return out
}

func (s *Store) ListPolicies() []*Policy {
	return s.queryPolicies(`SELECT ` + policyCols + ` FROM policies ORDER BY created_at`)
}

// PoliciesForResource returns every policy attached to a resource,
// across all roles. Used by the policy engine to find the row that
// matches the requesting user's role.
func (s *Store) PoliciesForResource(resourceID string) []*Policy {
	return s.queryPolicies(`SELECT `+policyCols+` FROM policies WHERE resource_id=$1`, resourceID)
}

func (s *Store) DeletePolicy(id string) (bool, error) {
	ctx, cancel := dbctx()
	defer cancel()
	tag, err := s.pool.Exec(ctx, `DELETE FROM policies WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// --- Audit (append-only, hash-chained) ---

const auditCols = `id, ts, user_id, username, role, resource_id, resource, action, decision, reason, prev_hash, hash`

// AppendAudit adds an entry to the hash chain. Inserts are serialised with
// an advisory lock so concurrent requests cannot fork the chain.
func (s *Store) AppendAudit(e *AuditEntry) error {
	ctx, cancel := dbctx()
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(727274)`); err != nil {
		return err
	}
	var prev string
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_log WHERE hash <> '' ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	e.Timestamp = NormalizeAuditTime(e.Timestamp)
	e.PrevHash = prev
	e.Hash = ComputeAuditHash(prev, e)
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_log (`+auditCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		e.ID, e.Timestamp, e.UserID, e.Username, string(e.Role), e.ResourceID, e.Resource,
		string(e.Action), string(e.Decision), e.Reason, e.PrevHash, e.Hash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func scanAudit(rows pgx.Rows) (*AuditEntry, error) {
	var e AuditEntry
	var role, action, decision string
	if err := rows.Scan(&e.ID, &e.Timestamp, &e.UserID, &e.Username, &role, &e.ResourceID,
		&e.Resource, &action, &decision, &e.Reason, &e.PrevHash, &e.Hash); err != nil {
		return nil, err
	}
	e.Role, e.Action, e.Decision = Role(role), Action(action), Decision(decision)
	e.Timestamp = e.Timestamp.UTC()
	return &e, nil
}

func (s *Store) queryAudit(query string, args ...any) []*AuditEntry {
	ctx, cancel := dbctx()
	defer cancel()
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		log.Printf("queryAudit: %v", err)
		return []*AuditEntry{}
	}
	defer rows.Close()
	out := []*AuditEntry{}
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			log.Printf("queryAudit scan: %v", err)
			continue
		}
		out = append(out, e)
	}
	return out
}

// ListAudit returns the newest `limit` entries, newest first.
func (s *Store) ListAudit(limit, offset int) []*AuditEntry {
	return s.queryAudit(`SELECT `+auditCols+` FROM audit_log ORDER BY seq DESC LIMIT $1 OFFSET $2`, limit, offset)
}

// ListAuditAsc returns the whole log oldest-first (for chain verification).
func (s *Store) ListAuditAsc() ([]*AuditEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT `+auditCols+` FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditCounts returns total / allow / deny counts without loading rows.
func (s *Store) AuditCounts() (total, allow, deny int) {
	ctx, cancel := dbctx()
	defer cancel()
	err := s.pool.QueryRow(ctx,
		`SELECT count(*), count(*) FILTER (WHERE decision='ALLOW'), count(*) FILTER (WHERE decision='DENY') FROM audit_log`,
	).Scan(&total, &allow, &deny)
	if err != nil {
		log.Printf("AuditCounts: %v", err)
	}
	return
}
