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
		return nil, fmt.Errorf("unsupported_grant_type: %s", req.GrantType)
	}
}

func (s *Server) grantAuthorizationCode(req *TokenRequest) (*TokenResponse, error) {
	if !s.ValidateClient(req.ClientID, req.ClientSecret) {
		return nil, fmt.Errorf("invalid_client: authentication failed")
	}

	client, _ := s.Clients.GetByID(req.ClientID)
	if !client.IsGrantTypeAllowed("authorization_code") {
		return nil, fmt.Errorf("unauthorized_client: authorization_code grant is not allowed for this client")
	}

	authCode, ok := s.AuthCodes.Get(req.Code)
	if !ok {
		return nil, fmt.Errorf("invalid_grant: authorization code not found or expired")
	}

	s.AuthCodes.Delete(req.Code)

	if authCode.ClientID != req.ClientID {
		return nil, fmt.Errorf("invalid_grant: authorization code was not issued to this client")
	}

	if authCode.RedirectURI != req.RedirectURI {
		return nil, fmt.Errorf("invalid_grant: redirect_uri mismatch")
	}

	if !VerifyPKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, req.CodeVerifier) {
		return nil, fmt.Errorf("invalid_grant: PKCE verification failed")
	}

	if _, err := ValidateClientScope(client, authCode.Scope); err != nil {
		return nil, fmt.Errorf("invalid_scope: authorization code scope no longer permitted for this client")
	}

	accessToken, expiresAt, err := s.Generator.GenerateAccessToken(authCode.ClientID, authCode.UserID, authCode.Scope)
	if err != nil {
		return nil, err
	}

	refreshToken := s.Generator.GenerateRefreshToken()
	refreshExpiry := s.Generator.RefreshExpiryTime()

	s.Tokens.CreateAccessToken(&TokenInfo{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Scope:       authCode.Scope,
		UserID:      authCode.UserID,
		ClientID:    authCode.ClientID,
		ExpiresAt:   expiresAt,
	})

	s.Tokens.CreateRefreshToken(refreshToken, &TokenInfo{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
		UserID:       authCode.UserID,
		ClientID:     authCode.ClientID,
		ExpiresAt:    refreshExpiry,
	})

	resp := &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.Generator.AccessExpiry.Seconds()),
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
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
	if !s.ValidateClient(req.ClientID, req.ClientSecret) {
		return nil, fmt.Errorf("invalid_client: authentication failed")
	}

	if s.PasswordAuthFunc == nil {
		return nil, fmt.Errorf("unauthorized_client: password grant not configured")
	}

	client, _ := s.Clients.GetByID(req.ClientID)
	if !client.IsGrantTypeAllowed("password") {
		return nil, fmt.Errorf("unauthorized_client: password grant is not allowed for this client")
	}

	scope, err := ValidateClientScope(client, req.Scope)
	if err != nil {
		return nil, err
	}

	userID, err := s.PasswordAuthFunc(context.Background(), req.ClientID, req.Username, req.Password)
	if err != nil {
		return nil, fmt.Errorf("invalid_grant: %v", err)
	}

	authTime := time.Now().Unix()

	accessToken, expiresAt, err := s.Generator.GenerateAccessToken(req.ClientID, userID, scope)
	if err != nil {
		return nil, err
	}

	refreshToken := s.Generator.GenerateRefreshToken()
	refreshExpiry := s.Generator.RefreshExpiryTime()

	s.Tokens.CreateAccessToken(&TokenInfo{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Scope:       scope,
		UserID:      userID,
		ClientID:    req.ClientID,
		ExpiresAt:   expiresAt,
	})

	s.Tokens.CreateRefreshToken(refreshToken, &TokenInfo{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Scope:        scope,
		UserID:       userID,
		ClientID:     req.ClientID,
		ExpiresAt:    refreshExpiry,
	})

	resp := &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.Generator.AccessExpiry.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scope,
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
	if !s.ValidateClient(req.ClientID, req.ClientSecret) {
		return nil, fmt.Errorf("invalid_client: authentication failed")
	}

	client, _ := s.Clients.GetByID(req.ClientID)
	if !client.IsGrantTypeAllowed("client_credentials") {
		return nil, fmt.Errorf("unauthorized_client: client_credentials grant is not allowed for this client")
	}

	scope, err := ValidateClientScope(client, req.Scope)
	if err != nil {
		return nil, err
	}
	if ContainsScope(scope, "openid") {
		return nil, fmt.Errorf("invalid_scope: openid scope is not allowed for client_credentials grant")
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
	if !s.ValidateClient(req.ClientID, req.ClientSecret) {
		return nil, fmt.Errorf("invalid_client: authentication failed")
	}

	client, _ := s.Clients.GetByID(req.ClientID)
	if !client.IsGrantTypeAllowed("refresh_token") {
		return nil, fmt.Errorf("unauthorized_client: refresh_token grant is not allowed for this client")
	}

	oldInfo, ok := s.Tokens.GetRefreshToken(req.RefreshToken)
	if !ok {
		return nil, fmt.Errorf("invalid_grant: refresh token not found")
	}

	if oldInfo.ClientID != req.ClientID {
		return nil, fmt.Errorf("invalid_grant: refresh token was not issued to this client")
	}

	scope := req.Scope
	if scope == "" {
		scope = oldInfo.Scope
	}
	scope, err := ValidateClientScope(client, scope)
	if err != nil {
		return nil, err
	}

	if req.Scope != "" && !isScopeNarrowed(scope, oldInfo.Scope) {
		return nil, fmt.Errorf("invalid_scope: requested scope exceeds the scope granted in the original authorization")
	}

	s.Tokens.DeleteRefreshToken(req.RefreshToken)
	s.Tokens.DeleteAccessToken(oldInfo.AccessToken)

	accessToken, expiresAt, err := s.Generator.GenerateAccessToken(oldInfo.ClientID, oldInfo.UserID, scope)
	if err != nil {
		return nil, err
	}

	newRefreshToken := s.Generator.GenerateRefreshToken()
	refreshExpiry := s.Generator.RefreshExpiryTime()

	s.Tokens.CreateAccessToken(&TokenInfo{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Scope:       scope,
		UserID:      oldInfo.UserID,
		ClientID:    oldInfo.ClientID,
		ExpiresAt:   expiresAt,
	})

	s.Tokens.CreateRefreshToken(newRefreshToken, &TokenInfo{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: newRefreshToken,
		Scope:        scope,
		UserID:       oldInfo.UserID,
		ClientID:     oldInfo.ClientID,
		ExpiresAt:    refreshExpiry,
	})

	resp := &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.Generator.AccessExpiry.Seconds()),
		RefreshToken: newRefreshToken,
		Scope:        scope,
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
