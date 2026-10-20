package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 default; required for authenticator-app compatibility
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// --- TOTP (RFC 6238) implemented with the standard library only ---

const (
	totpPeriod = 30 // seconds
	totpDigits = 6
	totpSkew   = 1 // accept +/- one 30s step for clock drift
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a random 160-bit secret, base32 encoded.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

func hotp(secret []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, code%mod)
}

func decodeSecret(secretB32 string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secretB32, " ", "")))
}

// TOTPAt returns the code valid at time t (exposed for tests / tooling).
func TOTPAt(secretB32 string, t time.Time) (string, error) {
	key, err := decodeSecret(secretB32)
	if err != nil {
		return "", err
	}
	return hotp(key, uint64(t.Unix()/totpPeriod)), nil
}

// VerifyTOTP checks code against the secret around time now. It only
// accepts a time-step strictly greater than lastStep, so a code that was
// already used (or an older one) is rejected: a captured code cannot be
// replayed. On success it returns the matched step, which the caller must
// persist atomically.
func VerifyTOTP(secretB32, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := decodeSecret(secretB32)
	if err != nil {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	matched := int64(-1)
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		step := cur + d
		want := hotp(key, uint64(step))
		// evaluate every candidate (no early exit) to keep timing uniform
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && step > lastStep {
			matched = step
		}
	}
	if matched < 0 {
		return 0, false
	}
	return matched, true
}

// ProvisioningURI is the otpauth:// URI authenticator apps import.
func ProvisioningURI(issuer, account, secretB32 string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secretB32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// --- Recovery codes ---

const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// GenerateRecoveryCodes returns n one-time codes (shown to the user once)
// and their SHA-256 hashes (what we store). The codes carry ~49 bits of
// entropy each, so a fast hash is sufficient.
func GenerateRecoveryCodes(n int) (codes []string, hashes []string, err error) {
	for i := 0; i < n; i++ {
		raw := make([]byte, 10)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, err
		}
		out := make([]byte, 10)
		for j, b := range raw {
			out[j] = recoveryAlphabet[int(b)%len(recoveryAlphabet)]
		}
		code := string(out[:5]) + "-" + string(out[5:])
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

func HashRecoveryCode(code string) string {
	code = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// LooksLikeRecoveryCode distinguishes "abcde-fghjk" from a 6-digit TOTP.
func LooksLikeRecoveryCode(code string) bool {
	return strings.Contains(code, "-") || len(strings.TrimSpace(code)) > totpDigits
}
