package server

import (
	"crypto/sha256"
	"encoding/base64"
)

func VerifyPKCE(challenge, method, verifier string) bool {
	if challenge == "" {
		return true
	}
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	case "plain":
		return verifier == challenge
	default:
		return false
	}
}
