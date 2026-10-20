package main

import (
	"net/http"
	"strings"
	"time"
)

// --- MFA enrolment & management (all require an authenticated session) ---

// POST /api/mfa/setup — generate a TOTP secret (not active until confirmed).
func (a *App) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	if p.User.MFAEnabled {
		writeError(w, http.StatusConflict, "MFA is already enabled; disable it first to re-enrol")
		return
	}
	secret, err := GenerateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate secret")
		return
	}
	enc, err := a.km.Seal([]byte(secret), mfaAAD(p.User.ID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to protect secret")
		return
	}
	if !a.audit(w, p.User, "", "", EventMFASetup, DecisionAllow, "MFA enrolment started") {
		return
	}
	if err := a.store.SetMFAPending(p.User.ID, enc); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":     secret,
		"otpauthUri": ProvisioningURI(a.cfg.MFAIssuer, p.User.Username, secret),
	})
}

// POST /api/mfa/enable {code} — confirm the authenticator works, activate MFA,
// and return one-time recovery codes (shown only now).
func (a *App) handleMFAEnable(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}
	user := p.User
	if user.MFAEnabled {
		writeError(w, http.StatusConflict, "MFA is already enabled")
		return
	}
	if user.MFASecretEnc == "" {
		writeError(w, http.StatusBadRequest, "start enrolment first (POST /api/mfa/setup)")
		return
	}
	ukey := "user:" + strings.ToLower(user.Username)
	if locked, retry := a.userLim.Check(ukey); locked {
		tooMany(w, retry)
		return
	}
	secret, err := a.km.Open(user.MFASecretEnc, mfaAAD(user.ID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stored secret unreadable; restart enrolment")
		return
	}
	step, good := VerifyTOTP(string(secret), req.Code, time.Now(), 0)
	if !good {
		a.userLim.Fail(ukey)
		a.auditBestEffort(user, "", "", EventMFAEnable, DecisionDeny, "wrong confirmation code")
		writeError(w, http.StatusUnauthorized, "invalid verification code")
		return
	}
	codes, hashes, err := GenerateRecoveryCodes(8)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate recovery codes")
		return
	}
	if !a.audit(w, user, "", "", EventMFAEnable, DecisionAllow, "MFA enabled (TOTP); 8 recovery codes issued") {
		return
	}
	if err := a.store.EnableMFA(user.ID, step, hashes); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to enable MFA")
		return
	}
	a.userLim.Success(ukey)
	a.sessions.MarkMFA(p.Token) // this session has just proven possession of the factor
	writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": true, "recoveryCodes": codes})
}

// POST /api/mfa/disable {password, code} — requires both factors.
func (a *App) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	if a.requireMFA {
		writeError(w, http.StatusForbidden, "MFA is mandatory on this deployment and cannot be disabled")
		return
	}
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.Password == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "password and code are required")
		return
	}
	user := p.User
	if !user.MFAEnabled {
		writeError(w, http.StatusConflict, "MFA is not enabled")
		return
	}
	ukey := "user:" + strings.ToLower(user.Username)
	if locked, retry := a.userLim.Check(ukey); locked {
		tooMany(w, retry)
		return
	}
	pwOK, _ := VerifyPassword(req.Password, user.PasswordHash, user.Salt)
	good, _ := a.verifySecondFactor(user, req.Code)
	if !pwOK || !good {
		a.userLim.Fail(ukey)
		a.auditBestEffort(user, "", "", EventMFADisable, DecisionDeny, "wrong password or code")
		writeError(w, http.StatusUnauthorized, "password or code incorrect")
		return
	}
	if !a.audit(w, user, "", "", EventMFADisable, DecisionAllow, "MFA disabled by the user") {
		return
	}
	if err := a.store.DisableMFA(user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to disable MFA")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": false})
}

// POST /api/users/{id}/mfa/reset — administrator recovery for a user who lost
// both their device and recovery codes. Revokes that user's sessions.
func (a *App) handleAdminResetMFA(w http.ResponseWriter, r *http.Request) {
	p, ok := a.requireRole(w, r, RoleAdmin)
	if !ok {
		return
	}
	target, ok := a.store.UserByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if !a.audit(w, p.User, target.ID, target.Username, EventMFAReset, DecisionAllow,
		"administrator reset MFA for "+target.Username) {
		return
	}
	if err := a.store.DisableMFA(target.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reset MFA")
		return
	}
	a.sessions.DeleteUser(target.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"reset": true})
}
