package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

type Client struct {
	ID              string
	Secret          string
	RedirectURIs    []string
	Scopes          []string
	AllowedGrantTypes []string
}

func (c *Client) IsGrantTypeAllowed(grantType string) bool {
	for _, gt := range c.AllowedGrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

type AuthorizationCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	Nonce               string
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            int64
	ExpiresAt           time.Time
}

type TokenInfo struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	Scope        string
	UserID       string
	ClientID     string
	ExpiresAt    time.Time
}

type ClientStore struct {
	clients sync.Map
}

func NewClientStore() *ClientStore {
	return &ClientStore{}
}

func (s *ClientStore) GetByID(id string) (*Client, bool) {
	v, ok := s.clients.Load(id)
	if !ok {
		return nil, false
	}
	c, _ := v.(*Client)
	return c, true
}

func (s *ClientStore) Set(client *Client) {
	s.clients.Store(client.ID, client)
}

type AuthCodeStore struct {
	codes sync.Map
}

func NewAuthCodeStore() *AuthCodeStore {
	return &AuthCodeStore{}
}

func (s *AuthCodeStore) Create(code *AuthorizationCode) error {
	s.codes.Store(code.Code, code)
	return nil
}

func (s *AuthCodeStore) Get(code string) (*AuthorizationCode, bool) {
	v, ok := s.codes.Load(code)
	if !ok {
		return nil, false
	}
	ac, _ := v.(*AuthorizationCode)
	if time.Now().After(ac.ExpiresAt) {
		s.codes.Delete(code)
		return nil, false
	}
	return ac, true
}

func (s *AuthCodeStore) Delete(code string) {
	s.codes.Delete(code)
}

type TokenStore struct {
	accessTokens  sync.Map
	refreshTokens sync.Map
}

func NewTokenStore() *TokenStore {
	return &TokenStore{}
}

func (s *TokenStore) CreateAccessToken(token *TokenInfo) error {
	s.accessTokens.Store(token.AccessToken, token)
	return nil
}

func (s *TokenStore) GetAccessToken(token string) (*TokenInfo, bool) {
	v, ok := s.accessTokens.Load(token)
	if !ok {
		return nil, false
	}
	ti, _ := v.(*TokenInfo)
	if time.Now().After(ti.ExpiresAt) {
		s.accessTokens.Delete(token)
		return nil, false
	}
	return ti, true
}

func (s *TokenStore) DeleteAccessToken(token string) {
	s.accessTokens.Delete(token)
}

func (s *TokenStore) CreateRefreshToken(tokenString string, info *TokenInfo) error {
	s.refreshTokens.Store(tokenString, info)
	return nil
}

func (s *TokenStore) GetRefreshToken(token string) (*TokenInfo, bool) {
	v, ok := s.refreshTokens.Load(token)
	if !ok {
		return nil, false
	}
	ti, _ := v.(*TokenInfo)
	if time.Now().After(ti.ExpiresAt) {
		s.refreshTokens.Delete(token)
		return nil, false
	}
	return ti, true
}

func (s *TokenStore) DeleteRefreshToken(token string) {
	s.refreshTokens.Delete(token)
}

func generateRandomString(byteLen int) string {
	b := make([]byte, byteLen)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func ContainsScope(scope, target string) bool {
	for _, s := range splitSpaces(scope) {
		if s == target {
			return true
		}
	}
	return false
}

func splitSpaces(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range split(s) {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func split(s string) []string {
	return fieldSplit(s, ' ')
}

func fieldSplit(s string, sep rune) []string {
	var parts []string
	start := 0
	for i, c := range s {
		if c == sep {
			if i > start {
				parts = append(parts, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}

func ShouldIncludeIDToken(scope, userID string, userStore *model.UserStore) bool {
	return ContainsScope(scope, "openid") && userID != "" && userStore != nil
}

func ValidateClientScope(client *Client, requestedScope string) (string, error) {
	if len(client.Scopes) == 0 {
		return requestedScope, nil
	}

	if requestedScope == "" {
		return strings.Join(client.Scopes, " "), nil
	}

	requested := splitSpaces(requestedScope)
	allowed := make(map[string]bool, len(client.Scopes))
	for _, s := range client.Scopes {
		allowed[s] = true
	}

	for _, s := range requested {
		if !allowed[s] {
			return "", fmt.Errorf("invalid_scope: scope %q is not allowed for client %q", s, client.ID)
		}
	}

	return requestedScope, nil
}

func isScopeNarrowed(requested, original string) bool {
	if original == "" {
		return true
	}
	originalScopes := make(map[string]bool, len(splitSpaces(original)))
	for _, s := range splitSpaces(original) {
		originalScopes[s] = true
	}
	for _, s := range splitSpaces(requested) {
		if !originalScopes[s] {
			return false
		}
	}
	return true
}
