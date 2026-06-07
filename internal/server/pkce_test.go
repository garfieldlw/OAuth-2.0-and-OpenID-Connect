package server

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyPKCE_S256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K79uhjU8d1lAO7-2N8Gv8JLm3c"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if !VerifyPKCE(challenge, "S256", verifier) {
		t.Error("expected S256 verification to pass with correct verifier")
	}

	if VerifyPKCE(challenge, "S256", "wrong-verifier-value") {
		t.Error("expected S256 verification to fail with wrong verifier")
	}
}

func TestVerifyPKCE_EmptyChallenge(t *testing.T) {
	if !VerifyPKCE("", "S256", "any-verifier") {
		t.Error("expected empty challenge to return true")
	}
}

func TestVerifyPKCE_UnsupportedMethod(t *testing.T) {
	if VerifyPKCE("some-challenge", "plain", "some-verifier") {
		t.Error("expected unsupported method to return false")
	}
}

func TestVerifyPKCE_ConstantTime(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K79uhjU8d1lAO7-2N8Gv8JLm3c"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Short wrong value (different length from challenge)
	if VerifyPKCE(challenge, "S256", "short") {
		t.Error("expected S256 verification to fail with short wrong verifier")
	}

	// Same-length wrong value: produce a different challenge of equal length
	wrongVerifier := "aBjftJeZ4CVP-mB92K79uhjU8d1lAO7-2N8Gv8JLm3cX"
	if VerifyPKCE(challenge, "S256", wrongVerifier) {
		t.Error("expected S256 verification to fail with same-length wrong verifier")
	}
}
