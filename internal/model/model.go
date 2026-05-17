package model

import (
	"crypto/rsa"
	"time"
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
	users map[string]*User
}

func NewUserStore() *UserStore {
	s := &UserStore{
		users: make(map[string]*User),
	}
	s.Set(&User{ID: "1", Username: "admin", Password: "admin", Email: "admin@example.com", Name: "Admin User"})
	s.Set(&User{ID: "2", Username: "test", Password: "test", Email: "test@example.com", Name: "Test User"})
	return s
}

func (s *UserStore) Set(u *User) {
	s.users[u.Username] = u
}

func (s *UserStore) GetByUsername(username string) (*User, bool) {
	u, ok := s.users[username]
	return u, ok
}

func (s *UserStore) GetByID(id string) (*User, bool) {
	for _, u := range s.users {
		if u.ID == id {
			return u, true
		}
	}
	return nil, false
}

type AppConfig struct {
	Issuer         string
	Port           int
	RSAPrivateKey  *rsa.PrivateKey
	RSAPublicKey   *rsa.PublicKey
	KeyID          string
	JWTSigningMethod string
	SecureCookie   bool
	RSAKeyPath     string
}

func DefaultAppConfig() *AppConfig {
	return &AppConfig{
		Issuer:           "http://localhost:9096",
		Port:             9096,
		JWTSigningMethod: "RS256",
	}
}

type OIDCDiscovery struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSETEndpoint                   string   `json:"jwks_uri"`
	RegistrationEndpoint             string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported,omitempty"`
}

type IDTokenClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
	Nonce    string `json:"nonce,omitempty"`
	AuthTime int64  `json:"auth_time,omitempty"`
	ACR      string `json:"acr,omitempty"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
}

type UserInfoResponse struct {
	Sub           string `json:"sub" example:"1"`
	Name          string `json:"name,omitempty" example:"Admin User"`
	Email         string `json:"email,omitempty" example:"admin@example.com"`
	EmailVerified bool   `json:"email_verified,omitempty" example:"true"`
}

// AuthorizeRequest represents the OAuth 2.0 / OIDC authorization endpoint parameters.
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" json:"response_type" example:"code"`
	ClientID            string `form:"client_id" json:"client_id" example:"000000"`
	RedirectURI         string `form:"redirect_uri" json:"redirect_uri" example:"http://localhost:9094"`
	Scope               string `form:"scope" json:"scope" example:"openid profile email"`
	State               string `form:"state" json:"state" example:"xyz123"`
	Nonce               string `form:"nonce" json:"nonce" example:"n-0S6_WzA2Mj"`
	CodeChallenge       string `form:"code_challenge" json:"code_challenge,omitempty"`
	CodeChallengeMethod string `form:"code_challenge_method" json:"code_challenge_method,omitempty" example:"S256"`
}

// TokenRequest represents the OAuth 2.0 token endpoint parameters.
type TokenRequest struct {
	GrantType    string `form:"grant_type" json:"grant_type" example:"authorization_code"`
	ClientID     string `form:"client_id" json:"client_id" example:"000000"`
	ClientSecret string `form:"client_secret" json:"client_secret" example:"999999"`
	Code         string `form:"code,omitempty" json:"code,omitempty"`
	RedirectURI  string `form:"redirect_uri,omitempty" json:"redirect_uri,omitempty" example:"http://localhost:9094"`
	Scope        string `form:"scope,omitempty" json:"scope,omitempty" example:"openid"`
	Username     string `form:"username,omitempty" json:"username,omitempty" example:"admin"`
	Password     string `form:"password,omitempty" json:"password,omitempty"`
	RefreshToken string `form:"refresh_token,omitempty" json:"refresh_token,omitempty"`
	CodeVerifier string `form:"code_verifier,omitempty" json:"code_verifier,omitempty"`
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

// AuthorizeCodeResponse represents the authorization code flow redirect response.
type AuthorizeCodeResponse struct {
	Code  string `json:"code" example:"ODk4YWY2Njkt..."`
	State string `json:"state,omitempty" example:"xyz123"`
}

// ErrorResponse represents a standard OAuth 2.0 error response.
type ErrorResponse struct {
	Error            string `json:"error" example:"invalid_request"`
	ErrorDescription string `json:"error_description,omitempty" example:"The request is missing a required parameter."` 
}

type SessionData struct {
	LoggedInUserID string
	ReturnURI      string
	Nonce          string
	RequestedAt    time.Time
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
