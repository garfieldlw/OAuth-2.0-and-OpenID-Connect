package service

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/server"
)

// TokenService handles token endpoint business logic and error mapping.
type TokenService struct {
	Server *server.Server
}

func NewTokenService(srv *server.Server) *TokenService {
	return &TokenService{Server: srv}
}

// TokenError is a custom error type that carries OAuth error code,
// description, and the appropriate HTTP status code.
type TokenError struct {
	Code        string
	Description string
	HTTPStatus  int
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// ProcessToken calls the server's Token method and maps any error to a
// TokenError with the appropriate OAuth error code and HTTP status.
func (s *TokenService) ProcessToken(req *server.TokenRequest) (*server.TokenResponse, error) {
	resp, err := s.Server.Token(req)
	if err != nil {
		errMsg := err.Error()
		status := http.StatusBadRequest
		if strings.HasPrefix(errMsg, "invalid_client") {
			status = http.StatusUnauthorized
		}
		return nil, &TokenError{
			Code:        ExtractOAuthError(errMsg),
			Description: errMsg,
			HTTPStatus:  status,
		}
	}
	return resp, nil
}

func (s *TokenService) ValidateBearer(authHeader string) (*server.TokenInfo, error) {
	ti, err := s.Server.ValidateBearerToken(authHeader)
	if err != nil {
		return nil, fmt.Errorf("invalid_token: %v", err)
	}
	return ti, nil
}
