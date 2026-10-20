package main

import "fmt"

// PolicyReader is the slice of the store the policy engine needs
// (an interface so the engine can be unit-tested without a database).
type PolicyReader interface {
	PoliciesForResource(resourceID string) []*Policy
}

// classLevel orders classifications by sensitivity.
var classLevel = map[Classification]int{
	ClassPublic:             0,
	ClassInternal:           1,
	ClassConfidential:       2,
	ClassHighlyConfidential: 3,
}

// roleClearance is the highest classification level a role may EVER
// touch, no matter what a policy row says. A policy can only grant access
// *within* the role's clearance — so a mistaken or malicious policy such
// as "EMPLOYEE may DOWNLOAD a HIGHLY_CONFIDENTIAL file" is still DENY.
var roleClearance = map[Role]int{
	RoleEmployee:  classLevel[ClassInternal],
	RoleHR:        classLevel[ClassConfidential],
	RoleHRManager: classLevel[ClassHighlyConfidential],
	RoleAdmin:     classLevel[ClassHighlyConfidential], // clearance only; access still needs an explicit policy
}

// RoleClearanceOK reports whether the role's clearance covers the class.
func RoleClearanceOK(role Role, class Classification) bool {
	return roleClearance[role] >= classLevel[class]
}

// mfaRequired: step-up authentication rules. HIGHLY_CONFIDENTIAL data
// needs an MFA-verified session for every action; deleting anything
// CONFIDENTIAL or above also does.
func mfaRequired(class Classification, action Action) bool {
	if class == ClassHighlyConfidential {
		return true
	}
	return class == ClassConfidential && action == ActionDelete
}

// AccessContext carries per-request facts about the caller's session.
type AccessContext struct {
	MFAVerified bool
}

// EvaluateAccess never trusts a valid session by itself. Every call
// re-checks identity, role, classification, the requested action, the
// session's assurance level and the policy attached to that resource.
//
// Rule order (first match wins, everything else is DENY):
//  1. Unknown action -> DENY.
//  2. Role clearance below the file's classification -> DENY
//     (policies cannot override this).
//  3. Classification demands MFA and the session has none -> DENY.
//  4. No policy for this resource+role, or policy lacks the action -> DENY.
//  5. Otherwise ALLOW.
//
// There is no administrator override: ADMIN is evaluated exactly like
// every other role and must be granted access by an explicit policy.
func EvaluateAccess(pr PolicyReader, user *User, file *FileResource, action Action, ctx AccessContext) (Decision, string) {
	if !IsFileAction(action) {
		return DecisionDeny, fmt.Sprintf("Unsupported action %q", action)
	}
	if _, known := classLevel[file.Classification]; !known {
		return DecisionDeny, fmt.Sprintf("Resource %q has unknown classification %q — DENY", file.Name, file.Classification)
	}
	if !RoleClearanceOK(user.Role, file.Classification) {
		return DecisionDeny, fmt.Sprintf(
			"Role %s is not cleared for %s data (resource %q) — DENY regardless of any policy",
			user.Role, file.Classification, file.Name)
	}
	if mfaRequired(file.Classification, action) && !ctx.MFAVerified {
		return DecisionDeny, fmt.Sprintf(
			"%s on %s data requires a session verified with multi-factor authentication (step-up) — DENY",
			action, file.Classification)
	}

	policies := pr.PoliciesForResource(file.ID)
	if len(policies) == 0 {
		return DecisionDeny, fmt.Sprintf(
			"No policy exists for resource %q — Zero-Trust default is DENY until an administrator grants access", file.Name)
	}
	var matched *Policy
	for _, p := range policies {
		if p.Role == user.Role {
			matched = p
			break
		}
	}
	if matched == nil {
		return DecisionDeny, fmt.Sprintf(
			"Role %s has no policy entry for resource %q (classification %s) — DENY by default",
			user.Role, file.Name, file.Classification)
	}
	for _, a := range matched.Actions {
		if a == action {
			return DecisionAllow, fmt.Sprintf(
				"Policy grants role %s the %s action on resource %q (classification %s)",
				user.Role, action, file.Name, file.Classification)
		}
	}
	return DecisionDeny, fmt.Sprintf(
		"Role %s is not authorized to perform %s on %q (classification %s); permitted actions for this role: %v",
		user.Role, action, file.Name, file.Classification, matched.Actions)
}
