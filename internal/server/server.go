package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

type Server struct {
	Clients     *ClientStore
	AuthCodes   *AuthCodeStore
	Tokens      *TokenStore
	Generator   *TokenGenerator
	UserStore   *model.UserStore

	PasswordAuthFunc func(ctx context.Context, clientID, username, password string) (string, error)
}

func NewServer(cfg *model.AppConfig, userStore *model.UserStore) *Server {
	generator := NewTokenGenerator(cfg.Issuer, cfg.RSAPrivateKey, cfg.KeyID, jwt.SigningMethodRS256)
	return &Server{
		Clients:   NewClientStore(),
		AuthCodes: NewAuthCodeStore(),
		Tokens:    NewTokenStore(),
		Generator: generator,
		UserStore: userStore,
	}
}

func (s *Server) RegisterClient(id, secret string, redirectURIs []string, scopes []string) {
	s.Clients.Set(&Client{
		ID:           id,
		Secret:       secret,
		RedirectURIs: redirectURIs,
		Scopes:       scopes,
	})
}

func (s *Server) ValidateClient(id, secret string) bool {
	client, ok := s.Clients.GetByID(id)
	if !ok {
		return false
	}
	return client.Secret == secret
}

func (s *Server) SetPasswordAuthHandler(fn func(ctx context.Context, clientID, username, password string) (string, error)) {
	s.PasswordAuthFunc = fn
}

func (s *Server) ValidateBearerToken(tokenString string) (*TokenInfo, error) {
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)

	claims, err := s.Generator.ValidateAccessToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid_token: %v", err)
	}

	ti, ok := s.Tokens.GetAccessToken(tokenString)
	if !ok {
		return nil, fmt.Errorf("invalid_token: token not found or revoked")
	}

	_ = claims
	return ti, nil
}
