package model

import (
	"crypto/rsa"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
	Avatar   string `json:"avatar,omitempty"`
}

type UserStore struct {
	mu         sync.RWMutex
	byID       map[string]*User
	byUsername map[string]*User
}

func NewUserStore() *UserStore {
	s := &UserStore{
		byID:       make(map[string]*User),
		byUsername: make(map[string]*User),
	}
	adminHash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	testHash, _ := bcrypt.GenerateFromPassword([]byte("test"), bcrypt.DefaultCost)
	s.Set(&User{ID: "1", Username: "admin", Password: string(adminHash), Email: "admin@example.com", Name: "Admin User"})
	s.Set(&User{ID: "2", Username: "test", Password: string(testHash), Email: "test@example.com", Name: "Test User"})
	return s
}

func (s *UserStore) Set(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[u.ID] = u
	s.byUsername[u.Username] = u
}

func (s *UserStore) GetByUsername(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byUsername[username]
	return u, ok
}

func (s *UserStore) GetByID(id string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	return u, ok
}

type AppConfig struct {
	Issuer           string
	Port             int
	RSAPrivateKey    *rsa.PrivateKey
	RSAPublicKey     *rsa.PublicKey
	KeyID            string
	JWTSigningMethod string
	SecureCookie     bool
	RSAKeyPath       string
}

func DefaultAppConfig() *AppConfig {
	return &AppConfig{
		Issuer:           "http://localhost:9096",
		Port:             9096,
		JWTSigningMethod: "RS256",
	}
}

type OIDCDiscovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSETEndpoint                    string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	ClaimsParameterSupported          bool     `json:"claims_parameter_supported"`
}

type UserInfoResponse struct {
	Sub           string `json:"sub" example:"1"`
	Name          string `json:"name,omitempty" example:"Admin User"`
	Email         string `json:"email,omitempty" example:"admin@example.com"`
	EmailVerified bool   `json:"email_verified,omitempty" example:"true"`
}

// TokenResponse represents the OAuth 2.0 / OIDC token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token" example:"eyJhbGciOiJSUzI1NiIs..."`
	TokenType    string `json:"token_type" example:"Bearer"`
	ExpiresIn    int64  `json:"expires_in" example:"7200"`
	RefreshToken string `json:"refresh_token,omitempty" example:"ODk4YWY2Njkt..."`
	Scope        string `json:"scope,omitempty" example:"openid profile"`
	IDToken      string `json:"id_token,omitempty" example:"eyJhbGciOiJSUzI1NiIs..."`
}

// ErrorResponse represents a standard OAuth 2.0 error response.
type ErrorResponse struct {
	Error            string `json:"error" example:"invalid_request"`
	ErrorDescription string `json:"error_description,omitempty" example:"The request is missing a required parameter."`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Redirect string `json:"redirect"`
}

type LoginStatusResponse struct {
	LoggedIn bool   `json:"logged_in"`
	Redirect string `json:"redirect,omitempty"`
}

type AuthContextResponse struct {
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"`
}

type AuthDecisionRequest struct {
	Authorize bool `json:"authorize"`
	Deny      bool `json:"deny"`
}

type AuthDecisionResponse struct {
	Redirect string `json:"redirect"`
}
