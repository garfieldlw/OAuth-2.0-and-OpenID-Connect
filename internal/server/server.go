package server

import (
	"context"
	"crypto/subtle"
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

func (s *Server) RegisterClient(id, secret string, redirectURIs []string, scopes []string, allowedGrantTypes []string) {
	s.Clients.Set(&Client{
		ID:               id,
		Secret:           secret,
		RedirectURIs:     redirectURIs,
		Scopes:           scopes,
		AllowedGrantTypes: allowedGrantTypes,
	})
}

func (s *Server) ValidateClient(id, secret string) bool {
	client, ok := s.Clients.GetByID(id)
	if !ok {
		return false
	}
	// RFC 6749 §2.3.1: constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(client.Secret), []byte(secret)) == 1
}

func (s *Server) SetPasswordAuthHandler(fn func(ctx context.Context, clientID, username, password string) (string, error)) {
	s.PasswordAuthFunc = fn
}

func (s *Server) IsRedirectURIRegistered(clientID, redirectURI string) bool {
	if redirectURI == "" {
		return false
	}
	if clientID != "" {
		client, ok := s.Clients.GetByID(clientID)
		if !ok {
			return false
		}
		return validateRedirectURI(client.RedirectURIs, redirectURI)
	}
	found := false
	s.Clients.clients.Range(func(_, v interface{}) bool {
		client, _ := v.(*Client)
		if validateRedirectURI(client.RedirectURIs, redirectURI) {
			found = true
			return false
		}
		return true
	})
	return found
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

func (s *Server) RevokeToken(token, tokenTypeHint, clientID string) error {
	client, ok := s.Clients.GetByID(clientID)
	if !ok {
		return fmt.Errorf("invalid_client: client not found")
	}
	_ = client

	switch tokenTypeHint {
	case "refresh_token":
		ti, ok := s.Tokens.GetRefreshToken(token)
		if ok {
			if ti.ClientID != clientID {
				return fmt.Errorf("invalid_client: token was not issued to this client")
			}
			s.Tokens.DeleteRefreshToken(token)
			s.Tokens.DeleteAccessToken(ti.AccessToken)
		}
	case "access_token":
		ti, ok := s.Tokens.GetAccessToken(token)
		if ok {
			if ti.ClientID != clientID {
				return fmt.Errorf("invalid_client: token was not issued to this client")
			}
			s.Tokens.DeleteAccessToken(token)
		}
	default:
		ti, ok := s.Tokens.GetAccessToken(token)
		if ok {
			if ti.ClientID == clientID {
				s.Tokens.DeleteAccessToken(token)
				return nil
			}
		}
		rti, ok := s.Tokens.GetRefreshToken(token)
		if ok {
			if rti.ClientID == clientID {
				s.Tokens.DeleteRefreshToken(token)
				s.Tokens.DeleteAccessToken(rti.AccessToken)
				return nil
			}
		}
	}
	return nil
}
