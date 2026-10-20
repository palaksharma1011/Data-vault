package main

import (
	"strings"
	"testing"
)

type fakePolicies map[string][]*Policy

func (f fakePolicies) PoliciesForResource(id string) []*Policy { return f[id] }

func file(class Classification) *FileResource {
	return &FileResource{ID: "f1", Name: "doc", Classification: class}
}

func grant(role Role, actions ...Action) fakePolicies {
	return fakePolicies{"f1": {{ID: "p1", ResourceID: "f1", Role: role, Actions: actions}}}
}

func TestClassificationOverridesPolicy(t *testing.T) {
	// Issue #1: EMPLOYEE + DOWNLOAD policy on a HIGHLY_CONFIDENTIAL file.
	emp := &User{Role: RoleEmployee}
	d, reason := EvaluateAccess(grant(RoleEmployee, ActionDownload), emp, file(ClassHighlyConfidential), ActionDownload, AccessContext{MFAVerified: true})
	if d != DecisionDeny || !strings.Contains(reason, "not cleared") {
		t.Fatalf("want clearance DENY, got %s: %s", d, reason)
	}
	// ...and HR (CONFIDENTIAL clearance) cannot touch HIGHLY_CONFIDENTIAL either
	d, _ = EvaluateAccess(grant(RoleHR, ActionRead), &User{Role: RoleHR}, file(ClassHighlyConfidential), ActionRead, AccessContext{MFAVerified: true})
	if d != DecisionDeny {
		t.Fatal("HR got HIGHLY_CONFIDENTIAL access")
	}
	// a cleared role with a policy is allowed
	d, _ = EvaluateAccess(grant(RoleHR, ActionRead), &User{Role: RoleHR}, file(ClassConfidential), ActionRead, AccessContext{})
	if d != DecisionAllow {
		t.Fatal("cleared role with policy was denied")
	}
}

func TestNoAdminBypass(t *testing.T) {
	// Issue: ADMIN must not get an implicit ALLOW.
	admin := &User{Role: RoleAdmin}
	for _, a := range []Action{ActionRead, ActionDownload, ActionDelete} {
		if d, _ := EvaluateAccess(fakePolicies{}, admin, file(ClassPublic), a, AccessContext{MFAVerified: true}); d != DecisionDeny {
			t.Fatalf("admin allowed %s without a policy", a)
		}
	}
	// with an explicit policy admin is allowed like anyone else
	if d, _ := EvaluateAccess(grant(RoleAdmin, ActionRead), admin, file(ClassInternal), ActionRead, AccessContext{}); d != DecisionAllow {
		t.Fatal("admin with explicit policy denied")
	}
}

func TestMFAStepUp(t *testing.T) {
	mgr := &User{Role: RoleHRManager}
	p := grant(RoleHRManager, ActionRead, ActionDownload, ActionDelete)
	hc := file(ClassHighlyConfidential)
	if d, r := EvaluateAccess(p, mgr, hc, ActionRead, AccessContext{MFAVerified: false}); d != DecisionDeny || !strings.Contains(r, "multi-factor") {
		t.Fatalf("HIGHLY_CONFIDENTIAL allowed without MFA: %s %s", d, r)
	}
	if d, _ := EvaluateAccess(p, mgr, hc, ActionRead, AccessContext{MFAVerified: true}); d != DecisionAllow {
		t.Fatal("HIGHLY_CONFIDENTIAL denied with MFA + policy")
	}
	conf := file(ClassConfidential)
	if d, _ := EvaluateAccess(p, mgr, conf, ActionDownload, AccessContext{}); d != DecisionAllow {
		t.Fatal("CONFIDENTIAL download should not need MFA")
	}
	if d, _ := EvaluateAccess(p, mgr, conf, ActionDelete, AccessContext{}); d != DecisionDeny {
		t.Fatal("CONFIDENTIAL delete should need MFA")
	}
}

func TestDefaultDenyAndActionScope(t *testing.T) {
	emp := &User{Role: RoleEmployee}
	if d, _ := EvaluateAccess(fakePolicies{}, emp, file(ClassInternal), ActionRead, AccessContext{}); d != DecisionDeny {
		t.Fatal("no policy must deny")
	}
	if d, _ := EvaluateAccess(grant(RoleHR, ActionRead), emp, file(ClassInternal), ActionRead, AccessContext{}); d != DecisionDeny {
		t.Fatal("policy for another role must deny")
	}
	p := grant(RoleEmployee, ActionRead)
	if d, _ := EvaluateAccess(p, emp, file(ClassInternal), ActionDownload, AccessContext{}); d != DecisionDeny {
		t.Fatal("unlisted action must deny")
	}
	if d, _ := EvaluateAccess(p, emp, file(ClassInternal), Action("FLY"), AccessContext{}); d != DecisionDeny {
		t.Fatal("unknown action must deny")
	}
	if d, _ := EvaluateAccess(p, emp, file(Classification("BOGUS")), ActionRead, AccessContext{}); d != DecisionDeny {
		t.Fatal("unknown classification must deny")
	}
}
