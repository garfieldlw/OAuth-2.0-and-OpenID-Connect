package server

import (
	"testing"
	"time"
)

func TestAuthCodeStore_ExpiredCodesNotRetrievable(t *testing.T) {
	store := NewAuthCodeStore()
	defer store.Close()

	store.Create(&AuthorizationCode{
		Code:      "expired-code",
		ClientID:  "test",
		ExpiresAt: time.Now().Add(-1 * time.Second),
	})

	store.Create(&AuthorizationCode{
		Code:      "valid-code",
		ClientID:  "test",
		ExpiresAt: time.Now().Add(1 * time.Minute),
	})

	_, ok := store.Get("expired-code")
	if ok {
		t.Error("expired code should not be retrievable")
	}

	_, ok = store.Get("valid-code")
	if !ok {
		t.Error("valid code should be retrievable")
	}
}

func TestTokenStore_ExpiredTokensNotRetrievable(t *testing.T) {
	store := NewTokenStore()
	defer store.Close()

	store.CreateAccessToken(&TokenInfo{
		AccessToken: "expired-access",
		ExpiresAt:   time.Now().Add(-1 * time.Second),
	})

	store.CreateAccessToken(&TokenInfo{
		AccessToken: "valid-access",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	_, ok := store.GetAccessToken("expired-access")
	if ok {
		t.Error("expired access token should not be retrievable")
	}

	_, ok = store.GetAccessToken("valid-access")
	if !ok {
		t.Error("valid access token should be retrievable")
	}
}

func TestGenerateRandomString_Success(t *testing.T) {
	s, err := generateRandomString(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) == 0 {
		t.Error("expected non-empty string")
	}
}

func TestGenerateRandomString_DifferentLengths(t *testing.T) {
	for _, length := range []int{16, 24, 32} {
		s, err := generateRandomString(length)
		if err != nil {
			t.Fatalf("length %d: unexpected error: %v", length, err)
		}
		if len(s) == 0 {
			t.Errorf("length %d: expected non-empty string", length)
		}
	}
}

func TestGenerateRandomString_Uniqueness(t *testing.T) {
	results := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := generateRandomString(32)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if results[s] {
			t.Fatal("duplicate random string generated")
		}
		results[s] = true
	}
}
