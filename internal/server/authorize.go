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
}

type AuthorizeResult struct {
	RedirectURI string
	Code        string
	State       string
}

func (s *Server) Authorize(req *AuthorizeRequest) (*AuthorizeResult, error) {
	client, ok := s.Clients.GetByID(req.ClientID)
	if !ok {
		return nil, fmt.Errorf("invalid_client: client %s not found", req.ClientID)
	}

	if !validateRedirectURI(client.RedirectURIs, req.RedirectURI) {
		return nil, fmt.Errorf("invalid_request: redirect_uri does not match any registered redirect URI for this client")
	}

	if req.RedirectURI == "" {
		return nil, fmt.Errorf("invalid_request: redirect_uri is required")
	}

	scope, err := ValidateClientScope(client, req.Scope)
	if err != nil {
		return nil, err
	}
	req.Scope = scope

	if req.ResponseType != "code" {
		return nil, fmt.Errorf("unsupported_response_type: %s (implicit and hybrid flows are removed per OAuth 2.1)", req.ResponseType)
	}

	return s.authorizeCode(req)
}

func (s *Server) authorizeCode(req *AuthorizeRequest) (*AuthorizeResult, error) {
	code := s.Generator.GenerateAuthorizationCode()

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
		ExpiresAt:           time.Now().Add(10 * time.Minute),
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
