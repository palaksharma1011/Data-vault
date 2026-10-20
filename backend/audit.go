package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// AuditSink is what the audit helpers need from the store.
type AuditSink interface {
	AppendAudit(e *AuditEntry) error
}

// LogAudit records one security-relevant event. It RETURNS the error:
// callers that gate access on the audit trail (file access, privileged
// changes, login) must refuse to proceed if the event could not be
// recorded (fail closed).
func LogAudit(sink AuditSink, user *User, resourceID, resourceName string, action Action, decision Decision, reason string) error {
	return LogEvent(sink, user.ID, user.Username, user.Role, resourceID, resourceName, action, decision, reason)
}

// LogEvent is LogAudit for events where there may be no authenticated
// user (e.g. a failed login for an unknown username).
func LogEvent(sink AuditSink, userID, username string, role Role, resourceID, resourceName string, action Action, decision Decision, reason string) error {
	return sink.AppendAudit(&AuditEntry{
		ID:         newID("audit"),
		Timestamp:  time.Now(),
		UserID:     userID,
		Username:   username,
		Role:       role,
		ResourceID: resourceID,
		Resource:   resourceName,
		Action:     action,
		Decision:   decision,
		Reason:     reason,
	})
}

// --- Tamper-evident hash chain ---
//
// Every entry stores hash = SHA256(prevHash || canonical(entry fields)).
// Editing, deleting or re-ordering any past row breaks every hash after
// it, which VerifyAuditChain detects. (The database additionally rejects
// UPDATE/DELETE on the table with a trigger; the chain catches an
// attacker who bypasses that, e.g. a DBA who drops the trigger.)

// NormalizeAuditTime fixes the timestamp to what PostgreSQL stores
// (UTC, microseconds) so the hash is reproducible after a round trip.
func NormalizeAuditTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

func ComputeAuditHash(prev string, e *AuditEntry) string {
	canon, _ := json.Marshal([]string{
		e.ID,
		NormalizeAuditTime(e.Timestamp).Format(time.RFC3339Nano),
		e.UserID, e.Username, string(e.Role),
		e.ResourceID, e.Resource,
		string(e.Action), string(e.Decision), e.Reason,
	})
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{0})
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil))
}

// AuditVerification is the result of checking the chain.
type AuditVerification struct {
	OK        bool   `json:"ok"`
	Checked   int    `json:"checked"`
	Legacy    int    `json:"legacyUnchained"`
	BrokenAt  string `json:"brokenAtEntryId,omitempty"`
	BrokenSeq int    `json:"brokenAtPosition,omitempty"`
	Message   string `json:"message"`
	HeadHash  string `json:"headHash"`
}

// VerifyAuditChain checks entries given oldest-first. Rows written before
// the chain existed (empty hash at the very start) are counted as legacy.
func VerifyAuditChain(entries []*AuditEntry) AuditVerification {
	res := AuditVerification{OK: true}
	prev := ""
	started := false
	for i, e := range entries {
		if !started && e.Hash == "" {
			res.Legacy++
			continue
		}
		started = true
		if e.PrevHash != prev || ComputeAuditHash(prev, e) != e.Hash {
			res.OK = false
			res.BrokenAt, res.BrokenSeq = e.ID, i+1
			res.Message = "audit chain broken: an entry was modified, removed or re-ordered at or before this position"
			res.HeadHash = prev
			return res
		}
		prev = e.Hash
		res.Checked++
	}
	res.HeadHash = prev
	res.Message = "audit chain intact"
	return res
}
