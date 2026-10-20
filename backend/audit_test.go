package main

import (
	"testing"
	"time"
)

func buildChain(n int) []*AuditEntry {
	var out []*AuditEntry
	prev := ""
	for i := 0; i < n; i++ {
		e := &AuditEntry{ID: newID("audit"), Timestamp: time.Now().Add(time.Duration(i) * time.Second),
			UserID: "u", Username: "alice", Role: RoleHR, Action: ActionRead, Decision: DecisionAllow, Reason: "ok"}
		e.Timestamp = NormalizeAuditTime(e.Timestamp)
		e.PrevHash = prev
		e.Hash = ComputeAuditHash(prev, e)
		prev = e.Hash
		out = append(out, e)
	}
	return out
}

func TestAuditChainIntact(t *testing.T) {
	if v := VerifyAuditChain(buildChain(10)); !v.OK || v.Checked != 10 {
		t.Fatalf("intact chain failed: %+v", v)
	}
}

func TestAuditChainDetectsEditDeleteReorder(t *testing.T) {
	c := buildChain(6)
	c[2].Reason = "tampered"
	if v := VerifyAuditChain(c); v.OK || v.BrokenSeq != 3 {
		t.Fatalf("edit not detected: %+v", v)
	}
	c = buildChain(6)
	c = append(c[:2], c[3:]...) // delete entry 3
	if v := VerifyAuditChain(c); v.OK {
		t.Fatal("deletion not detected")
	}
	c = buildChain(6)
	c[1], c[2] = c[2], c[1]
	if v := VerifyAuditChain(c); v.OK {
		t.Fatal("reorder not detected")
	}
}

func TestAuditChainLegacyRows(t *testing.T) {
	legacy := []*AuditEntry{{ID: "old1"}, {ID: "old2"}}
	v := VerifyAuditChain(append(legacy, buildChain(3)...))
	if !v.OK || v.Legacy != 2 || v.Checked != 3 {
		t.Fatalf("legacy handling wrong: %+v", v)
	}
}
