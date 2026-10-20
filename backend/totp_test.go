package main

import (
	"testing"
	"time"
)

// RFC 6238 Appendix B vectors (SHA-1, secret "12345678901234567890"),
// truncated to 6 digits.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPRFC6238Vectors(t *testing.T) {
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range cases {
		got, err := TOTPAt(rfcSecret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Errorf("t=%d: got %s want %s (%v)", ts, got, want, err)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	now := time.Unix(1700000000, 0)
	code, _ := TOTPAt(rfcSecret, now)
	step, ok := VerifyTOTP(rfcSecret, code, now, 0)
	if !ok {
		t.Fatal("valid code rejected")
	}
	// replay of the same code must fail once its step is recorded
	if _, ok := VerifyTOTP(rfcSecret, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	// +/-1 step tolerated, +/-3 steps not
	prev, _ := TOTPAt(rfcSecret, now.Add(-30*time.Second))
	if _, ok := VerifyTOTP(rfcSecret, prev, now, 0); !ok {
		t.Fatal("code from previous step rejected")
	}
	old, _ := TOTPAt(rfcSecret, now.Add(-90*time.Second))
	if _, ok := VerifyTOTP(rfcSecret, old, now, 0); ok {
		t.Fatal("stale code accepted")
	}
	for _, bad := range []string{"", "12345", "abcdef", "1234567"} {
		if _, ok := VerifyTOTP(rfcSecret, bad, now, 0); ok {
			t.Fatalf("malformed code %q accepted", bad)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := GenerateRecoveryCodes(8)
	if err != nil || len(codes) != 8 || len(hashes) != 8 {
		t.Fatal("bad generation")
	}
	if HashRecoveryCode(codes[0]) != hashes[0] || HashRecoveryCode(" "+codes[0]+" ") != hashes[0] {
		t.Fatal("hash not stable / not normalised")
	}
	if !LooksLikeRecoveryCode(codes[0]) || LooksLikeRecoveryCode("123456") {
		t.Fatal("recovery-code detection wrong")
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatal("duplicate recovery code")
		}
		seen[c] = true
	}
}

func TestProvisioningURI(t *testing.T) {
	u := ProvisioningURI("Zero-Trust Vault", "alice", "ABC234")
	for _, want := range []string{"otpauth://totp/", "secret=ABC234", "issuer=Zero-Trust+Vault", "digits=6", "period=30"} {
		if !contains(u, want) {
			t.Errorf("uri %q missing %q", u, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
