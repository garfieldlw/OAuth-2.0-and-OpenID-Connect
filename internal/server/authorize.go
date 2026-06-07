package server

import (
	"fmt"
	"time"
)

type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string
	AuthTime            int64
}

type AuthorizeResult struct {
	RedirectURI string
	Code        string
	State       string
}

type AuthorizeError struct {
	*OAuthError
	RedirectURI string
	State       string
}

func (s *Server) Authorize(req *AuthorizeRequest) (*AuthorizeResult, error) {
	client, ok := s.Clients.GetByID(req.ClientID)
	if !ok {
		return nil, &AuthorizeError{
			OAuthError: ErrInvalidClient(fmt.Sprintf("client %s not found", req.ClientID)),
		}
	}

	if !validateRedirectURI(client.RedirectURIs, req.RedirectURI) {
		return nil, &AuthorizeError{
			OAuthError: ErrInvalidRequest("redirect_uri does not match any registered redirect URI for this client"),
		}
	}

	if req.RedirectURI == "" {
		return nil, &AuthorizeError{
			OAuthError: ErrInvalidRequest("redirect_uri is required"),
		}
	}

	// Per RFC 6749 §4.1.2.1: errors after redirect_uri is validated must be
	// returned by redirecting to the redirect_uri with error parameters.
	scope, err := ValidateClientScope(client, req.Scope)
	if err != nil {
		return nil, &AuthorizeError{
			OAuthError:  ErrInvalidScope(err.Error()),
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}
	}
	req.Scope = scope

	if req.CodeChallenge == "" {
		return nil, &AuthorizeError{
			OAuthError:  ErrInvalidRequest("PKCE code_challenge is required per OAuth 2.1 (RFC 9728 §7.1)"),
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}
	}

	if req.CodeChallengeMethod != "S256" {
		return nil, &AuthorizeError{
			OAuthError:  ErrInvalidRequest("code_challenge_method must be S256 per OAuth 2.1 (RFC 9728 §7.1)"),
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}
	}

	if req.ResponseType != "code" {
		return nil, &AuthorizeError{
			OAuthError:  ErrUnsupportedResponseType(fmt.Sprintf("%s (implicit and hybrid flows are removed per OAuth 2.1)", req.ResponseType)),
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}
	}

	return s.authorizeCode(req)
}

func (s *Server) authorizeCode(req *AuthorizeRequest) (*AuthorizeResult, error) {
	code, err := s.Generator.GenerateAuthorizationCode()
	if err != nil {
		return nil, fmt.Errorf("server_error: failed to generate authorization code: %w", err)
	}

	s.AuthCodes.Create(&AuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		UserID:              req.UserID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Nonce:               req.Nonce,
		ResponseType:        req.ResponseType,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		AuthTime:            req.AuthTime,
		ExpiresAt:           time.Now().Add(1 * time.Minute),
	})

	return &AuthorizeResult{
		RedirectURI: req.RedirectURI,
		Code:        code,
		State:       req.State,
	}, nil
}

func validateRedirectURI(registeredURIs []string, redirectURI string) bool {
	if redirectURI == "" {
		return false
	}
	for _, registered := range registeredURIs {
		if redirectURI == registered {
			return true
		}
	}
	return false
}
