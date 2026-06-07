package server

import (
	"context"
	"fmt"
	"time"
)

type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	Code         string
	RedirectURI  string
	Scope        string
	Username     string
	Password     string
	RefreshToken string
	CodeVerifier string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

func (s *Server) Token(req *TokenRequest) (*TokenResponse, error) {
	switch req.GrantType {
	case "authorization_code":
		return s.grantAuthorizationCode(req)
	case "password":
		return s.grantPassword(req)
	case "client_credentials":
		return s.grantClientCredentials(req)
	case "refresh_token":
		return s.grantRefreshToken(req)
	default:
		return nil, ErrUnsupportedGrantType(req.GrantType)
	}
}

// validateAndAuthenticate validates client credentials and checks that the client
// is allowed to use the specified grant type.
func (s *Server) validateAndAuthenticate(clientID, clientSecret, grantType string) (*Client, error) {
	if !s.ValidateClient(clientID, clientSecret) {
		return nil, ErrInvalidClient("authentication failed")
	}
	client, _ := s.Clients.GetByID(clientID)
	if !client.IsGrantTypeAllowed(grantType) {
		return nil, ErrUnauthorizedClient(fmt.Sprintf("%s grant is not allowed for this client", grantType))
	}
	return client, nil
}

// issueTokenPair generates an access token and refresh token, stores both, and returns
// a partially populated TokenResponse. The caller should set IDToken if applicable.
func (s *Server) issueTokenPair(clientID, userID, scope string) (*TokenResponse, error) {
	accessToken, expiresAt, err := s.Generator.GenerateAccessToken(clientID, userID, scope)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.Generator.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("server_error: failed to generate refresh token: %w", err)
	}
	refreshExpiry := s.Generator.RefreshExpiryTime()

	s.Tokens.CreateAccessToken(&TokenInfo{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Scope:       scope,
		UserID:      userID,
		ClientID:    clientID,
		ExpiresAt:   expiresAt,
	})

	s.Tokens.CreateRefreshToken(refreshToken, &TokenInfo{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Scope:        scope,
		UserID:       userID,
		ClientID:     clientID,
		ExpiresAt:    refreshExpiry,
	})

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.Generator.AccessExpiry.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}

func (s *Server) grantAuthorizationCode(req *TokenRequest) (*TokenResponse, error) {
	client, err := s.validateAndAuthenticate(req.ClientID, req.ClientSecret, "authorization_code")
	if err != nil {
		return nil, err
	}

	authCode, ok := s.AuthCodes.Get(req.Code)
	if !ok {
		return nil, ErrInvalidGrant("authorization code not found or expired")
	}

	s.AuthCodes.Delete(req.Code)

	if authCode.ClientID != req.ClientID {
		return nil, ErrInvalidGrant("authorization code was not issued to this client")
	}

	if authCode.RedirectURI != req.RedirectURI {
		return nil, ErrInvalidGrant("redirect_uri mismatch")
	}

	if !VerifyPKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, req.CodeVerifier) {
		return nil, ErrInvalidGrant("PKCE verification failed")
	}

	if _, err := ValidateClientScope(client, authCode.Scope); err != nil {
		return nil, ErrInvalidScope("authorization code scope no longer permitted for this client")
	}

	resp, err := s.issueTokenPair(authCode.ClientID, authCode.UserID, authCode.Scope)
	if err != nil {
		return nil, err
	}

	if ShouldIncludeIDToken(authCode.Scope, authCode.UserID, s.UserStore) {
		user, _ := s.UserStore.GetByID(authCode.UserID)
		idToken, err := s.Generator.GenerateIDToken(authCode.ClientID, authCode.UserID, authCode.Nonce, authCode.AuthTime, user, authCode.Scope)
		if err == nil {
			resp.IDToken = idToken
		}
	}

	return resp, nil
}

func (s *Server) grantPassword(req *TokenRequest) (*TokenResponse, error) {
	client, err := s.validateAndAuthenticate(req.ClientID, req.ClientSecret, "password")
	if err != nil {
		return nil, err
	}

	if s.PasswordAuthFunc == nil {
		return nil, ErrUnauthorizedClient("password grant not configured")
	}

	scope, err := ValidateClientScope(client, req.Scope)
	if err != nil {
		return nil, err
	}

	userID, err := s.PasswordAuthFunc(context.Background(), req.ClientID, req.Username, req.Password)
	if err != nil {
		return nil, ErrInvalidGrant(err.Error())
	}

	authTime := time.Now().Unix()

	resp, err := s.issueTokenPair(req.ClientID, userID, scope)
	if err != nil {
		return nil, err
	}

	if ShouldIncludeIDToken(scope, userID, s.UserStore) {
		user, _ := s.UserStore.GetByID(userID)
		idToken, err := s.Generator.GenerateIDToken(req.ClientID, userID, "", authTime, user, scope)
		if err == nil {
			resp.IDToken = idToken
		}
	}

	return resp, nil
}

func (s *Server) grantClientCredentials(req *TokenRequest) (*TokenResponse, error) {
	client, err := s.validateAndAuthenticate(req.ClientID, req.ClientSecret, "client_credentials")
	if err != nil {
		return nil, err
	}

	scope, err := ValidateClientScope(client, req.Scope)
	if err != nil {
		return nil, err
	}
	if ContainsScope(scope, "openid") {
		return nil, ErrInvalidScope("openid scope is not allowed for client_credentials grant")
	}

	accessToken, expiresAt, err := s.Generator.GenerateAccessToken(req.ClientID, "", scope)
	if err != nil {
		return nil, err
	}

	s.Tokens.CreateAccessToken(&TokenInfo{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Scope:       scope,
		UserID:      "",
		ClientID:    req.ClientID,
		ExpiresAt:   expiresAt,
	})

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.Generator.AccessExpiry.Seconds()),
		Scope:       scope,
	}, nil
}

func (s *Server) grantRefreshToken(req *TokenRequest) (*TokenResponse, error) {
	client, err := s.validateAndAuthenticate(req.ClientID, req.ClientSecret, "refresh_token")
	if err != nil {
		return nil, err
	}

	oldInfo, ok := s.Tokens.GetRefreshToken(req.RefreshToken)
	if !ok {
		return nil, ErrInvalidGrant("refresh token not found")
	}

	if oldInfo.ClientID != req.ClientID {
		return nil, ErrInvalidGrant("refresh token was not issued to this client")
	}

	scope := req.Scope
	if scope == "" {
		scope = oldInfo.Scope
	}
	scope, err = ValidateClientScope(client, scope)
	if err != nil {
		return nil, err
	}

	if req.Scope != "" && !isScopeNarrowed(scope, oldInfo.Scope) {
		return nil, ErrInvalidScope("requested scope exceeds the scope granted in the original authorization")
	}

	s.Tokens.DeleteRefreshToken(req.RefreshToken)
	s.Tokens.DeleteAccessToken(oldInfo.AccessToken)

	resp, err := s.issueTokenPair(oldInfo.ClientID, oldInfo.UserID, scope)
	if err != nil {
		return nil, err
	}

	if ShouldIncludeIDToken(scope, oldInfo.UserID, s.UserStore) {
		user, _ := s.UserStore.GetByID(oldInfo.UserID)
		idToken, err := s.Generator.GenerateIDToken(oldInfo.ClientID, oldInfo.UserID, "", time.Now().Unix(), user, scope)
		if err == nil {
			resp.IDToken = idToken
		}
	}

	return resp, nil
}
