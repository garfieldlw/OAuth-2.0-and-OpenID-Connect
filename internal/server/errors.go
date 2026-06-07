package server

import "fmt"

// OAuthError represents a structured OAuth 2.0 protocol error with code and description.
type OAuthError struct {
	Code        string
	Description string
}

func (e *OAuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func ErrInvalidClient(desc string) *OAuthError {
	return &OAuthError{"invalid_client", desc}
}

func ErrInvalidGrant(desc string) *OAuthError {
	return &OAuthError{"invalid_grant", desc}
}

func ErrInvalidScope(desc string) *OAuthError {
	return &OAuthError{"invalid_scope", desc}
}

func ErrUnsupportedGrantType(desc string) *OAuthError {
	return &OAuthError{"unsupported_grant_type", desc}
}

func ErrUnauthorizedClient(desc string) *OAuthError {
	return &OAuthError{"unauthorized_client", desc}
}

func ErrInvalidRequest(desc string) *OAuthError {
	return &OAuthError{"invalid_request", desc}
}

func ErrUnsupportedResponseType(desc string) *OAuthError {
	return &OAuthError{"unsupported_response_type", desc}
}

func ErrServerError(desc string) *OAuthError {
	return &OAuthError{"server_error", desc}
}
