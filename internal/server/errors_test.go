package server

import (
	"errors"
	"fmt"
	"testing"
)

func TestOAuthError_Error(t *testing.T) {
	err := ErrInvalidClient("authentication failed")
	expected := "invalid_client: authentication failed"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestOAuthError_As(t *testing.T) {
	err := ErrInvalidGrant("code not found")
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Error("should be able to extract OAuthError via errors.As")
	}
	if oauthErr.Code != "invalid_grant" {
		t.Errorf("got code %q, want %q", oauthErr.Code, "invalid_grant")
	}
}

func TestOAuthError_Wrapped(t *testing.T) {
	inner := ErrInvalidScope("openid not allowed")
	wrapped := fmt.Errorf("token failed: %w", inner)
	var oauthErr *OAuthError
	if !errors.As(wrapped, &oauthErr) {
		t.Error("should be able to extract OAuthError from wrapped error")
	}
}

func TestAllErrorConstructors(t *testing.T) {
	tests := []struct {
		name string
		err  *OAuthError
		code string
	}{
		{"invalid_client", ErrInvalidClient("desc"), "invalid_client"},
		{"invalid_grant", ErrInvalidGrant("desc"), "invalid_grant"},
		{"invalid_scope", ErrInvalidScope("desc"), "invalid_scope"},
		{"unsupported_grant_type", ErrUnsupportedGrantType("desc"), "unsupported_grant_type"},
		{"unauthorized_client", ErrUnauthorizedClient("desc"), "unauthorized_client"},
		{"invalid_request", ErrInvalidRequest("desc"), "invalid_request"},
		{"unsupported_response_type", ErrUnsupportedResponseType("desc"), "unsupported_response_type"},
		{"server_error", ErrServerError("desc"), "server_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.code {
				t.Errorf("got code %q, want %q", tt.err.Code, tt.code)
			}
		})
	}
}
