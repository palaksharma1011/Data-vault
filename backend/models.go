package main

import "time"

// Role is a user's assigned role. Roles are the identity attribute the
// policy engine evaluates against — a successful login never implies
// access to a resource.
type Role string

const (
	RoleAdmin     Role = "ADMIN"
	RoleHR        Role = "HR"
	RoleHRManager Role = "HR_MANAGER"
	RoleEmployee  Role = "EMPLOYEE"
)

// Classification is the sensitivity label attached to a stored resource.
type Classification string

const (
	ClassPublic             Classification = "PUBLIC"
	ClassInternal           Classification = "INTERNAL"
	ClassConfidential       Classification = "CONFIDENTIAL"
	ClassHighlyConfidential Classification = "HIGHLY_CONFIDENTIAL"
)

// Action is an operation a user may attempt against a resource.
type Action string

const (
	ActionRead     Action = "READ"
	ActionDownload Action = "DOWNLOAD"
	ActionDelete   Action = "DELETE"
)

// Security events that are not file-access requests but must still be
// audited. They share the AuditEntry.Action column.
const (
	EventLogin         Action = "LOGIN"
	EventLogout        Action = "LOGOUT"
	EventMFAVerify     Action = "MFA_VERIFY"
	EventMFASetup      Action = "MFA_SETUP"
	EventMFAEnable     Action = "MFA_ENABLE"
	EventMFADisable    Action = "MFA_DISABLE"
	EventMFAReset      Action = "MFA_RESET"
	EventUserCreate    Action = "USER_CREATE"
	EventFileUpload    Action = "FILE_UPLOAD"
	EventPolicyCreate  Action = "POLICY_CREATE"
	EventPolicyDelete  Action = "POLICY_DELETE"
	EventIntegrityFail Action = "INTEGRITY_FAILURE"
)

// IsFileAction reports whether a is an action a user may request on a file.
func IsFileAction(a Action) bool {
	return a == ActionRead || a == ActionDownload || a == ActionDelete
}

// IsValidRole / IsValidClassification are used for input validation.
func IsValidRole(r Role) bool {
	switch r {
	case RoleAdmin, RoleHR, RoleHRManager, RoleEmployee:
		return true
	}
	return false
}

func IsValidClassification(c Classification) bool {
	switch c {
	case ClassPublic, ClassInternal, ClassConfidential, ClassHighlyConfidential:
		return true
	}
	return false
}

// Decision is the explicit outcome of a policy evaluation. Zero-Trust
// requires this to always be one of these two values — there is no
// implicit allow.
type Decision string

const (
	DecisionAllow Decision = "ALLOW"
	DecisionDeny  Decision = "DENY"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"passwordHash"`
	Salt         string    `json:"salt"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"createdAt"`

	// MFA (TOTP). The secret is stored encrypted under the master key and
	// never serialised to API clients.
	MFAEnabled     bool     `json:"-"`
	MFASecretEnc   string   `json:"-"`
	MFALastStep    int64    `json:"-"` // last accepted TOTP time-step (replay protection)
	RecoveryHashes []string `json:"-"` // SHA-256 of unused one-time recovery codes
}

// SafeUser is the representation returned over the API — never the
// password hash or salt.
type SafeUser struct {
	ID         string    `json:"id"`
	Username   string    `json:"username"`
	Role       Role      `json:"role"`
	CreatedAt  time.Time `json:"createdAt"`
	MFAEnabled bool      `json:"mfaEnabled"`
}

func (u User) Safe() SafeUser {
	return SafeUser{ID: u.ID, Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt, MFAEnabled: u.MFAEnabled}
}

// FileResource is a stored, encrypted file. Plaintext never touches
// disk: EncPath points at the AES-256-GCM ciphertext, Nonce is the
// per-file random nonce, and Key is stored only in encrypted form via
// the key-management module (see crypto.go).
type FileResource struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Classification Classification `json:"classification"`
	OwnerID        string         `json:"-"`
	EncPath        string         `json:"-"`
	Nonce          string         `json:"-"` // legacy (EncVersion 1) single-shot nonce
	WrappedKey     string         `json:"-"` // DEK wrapped by master key
	EncVersion     int            `json:"-"` // 1 = legacy single-shot GCM, 2 = chunked GCM with AAD
	Size           int64          `json:"size"`
	UploadedAt     time.Time      `json:"uploadedAt"`
}

// FileView is the only representation of a file ever sent to API
// clients: no storage path, nonce, wrapped key or owner.
type FileView struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Classification Classification `json:"classification"`
	Size           int64          `json:"size"`
	UploadedAt     time.Time      `json:"uploadedAt"`
}

func (f *FileResource) View() FileView {
	return FileView{ID: f.ID, Name: f.Name, Classification: f.Classification, Size: f.Size, UploadedAt: f.UploadedAt}
}

// Policy binds a role to the set of actions it may perform on a specific
// resource. Absence of a matching policy is an implicit DENY — this is
// the core Zero-Trust rule enforced by the policy engine.
type Policy struct {
	ID         string    `json:"id"`
	ResourceID string    `json:"resourceId"`
	Role       Role      `json:"role"`
	Actions    []Action  `json:"actions"`
	CreatedAt  time.Time `json:"createdAt"`
}

// AuditEntry records every security-sensitive action: who, what, on
// which resource, the decision, and why.
type AuditEntry struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	UserID     string    `json:"userId"`
	Username   string    `json:"username"`
	Role       Role      `json:"role"`
	ResourceID string    `json:"resourceId"`
	Resource   string    `json:"resource"`
	Action     Action    `json:"action"`
	Decision   Decision  `json:"decision"`
	Reason     string    `json:"reason"`

	// Tamper-evidence: each entry commits to the previous entry's hash.
	PrevHash string `json:"prevHash"`
	Hash     string `json:"hash"`
}
