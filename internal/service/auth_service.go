package service

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

// AuthService handles login authentication and authorization decisions.
// It does not depend on Gin or session packages — the handler bridges between those and this service.
type AuthService struct {
	UserStore *model.UserStore
}

func NewAuthService(userStore *model.UserStore) *AuthService {
	return &AuthService{UserStore: userStore}
}

// SessionData is the session state passed from the handler layer.
type SessionData struct {
	LoggedInUserID   string
	LoggedInUsername string
	ReturnURI        string
	AuthTime         int64
}

type LoginResult struct {
	Redirect string
	UserID   string
	Username string
}

func (s *AuthService) Authenticate(username, password string) (userID string, ok bool) {
	user, found := s.UserStore.GetByUsername(username)
	if !found || user.Password != password {
		return "", false
	}
	return user.ID, true
}

func (s *AuthService) GetLoginStatus(sessionData *SessionData) (loggedIn bool, redirect string) {
	if sessionData.LoggedInUserID != "" {
		redirect := sessionData.ReturnURI
		if redirect == "" {
			redirect = "/auth"
		}
		return true, redirect
	}
	return false, ""
}

func (s *AuthService) GetLoginRedirect(sessionData *SessionData) string {
	if sessionData.ReturnURI != "" {
		return sessionData.ReturnURI
	}
	return "/auth"
}

// ProcessAuthDecision handles the user's authorize/deny consent decision.
// Returns the redirect URI for the browser to navigate to.
// For deny: appends error=access_denied to the ReturnURI query.
// For authorize: returns the stored ReturnURI (the original /oauth/authorize URL).
func (s *AuthService) ProcessAuthDecision(sessionData *SessionData, authorize bool, deny bool) (string, error) {
	returnURI := sessionData.ReturnURI

	if deny {
		if returnURI != "" {
			parsed, parseErr := url.Parse(returnURI)
			if parseErr == nil {
				q := parsed.Query()
				q.Set("error", "access_denied")
				q.Set("error_description", "The resource owner denied the request")
				if state := q.Get("state"); state != "" {
					q.Set("state", state)
				}
				parsed.RawQuery = q.Encode()
				return parsed.String(), nil
			}
		}
		return "/login", nil
	}

	if authorize {
		if returnURI != "" {
			return returnURI, nil
		}
		return "/auth", nil
	}

	return "", fmt.Errorf("must specify authorize or deny")
}

func (s *AuthService) ProcessLogout() []string {
	return []string{"LoggedInUserID", "LoggedInUsername", "ReturnURI", "Nonce"}
}

// GetAuthorizeSessionCheck checks if the user is authenticated for the authorize flow.
// Returns (userID, true) if logged in, or ("", false) if the user needs to log in.
// When needsLogin is true, the handler should save the request URI as ReturnURI
// in the session and redirect to /login.
func (s *AuthService) GetAuthorizeSessionCheck(sessionData *SessionData) (userID string, needsLogin bool) {
	if sessionData.LoggedInUserID == "" {
		return "", true
	}
	return sessionData.LoggedInUserID, false
}

func BuildDenyRedirect(returnURI string) string {
	if returnURI == "" {
		return "/login"
	}
	parsed, err := url.Parse(returnURI)
	if err != nil {
		return "/login"
	}
	q := parsed.Query()
	q.Set("error", "access_denied")
	q.Set("error_description", "The resource owner denied the request")
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// ExtractOAuthError maps an error message to a standard OAuth 2.0 error code.
func ExtractOAuthError(msg string) string {
	parts := strings.SplitN(msg, ":", 2)
	errCode := parts[0]
	switch {
	case strings.Contains(errCode, "invalid_client"):
		return "invalid_client"
	case strings.Contains(errCode, "invalid_grant"):
		return "invalid_grant"
	case strings.Contains(errCode, "invalid_request"):
		return "invalid_request"
	case strings.Contains(errCode, "invalid_scope"):
		return "invalid_scope"
	case strings.Contains(errCode, "unsupported_grant_type"):
		return "unsupported_grant_type"
	case strings.Contains(errCode, "unsupported_response_type"):
		return "unsupported_response_type"
	case strings.Contains(errCode, "unauthorized_client"):
		return "unauthorized_client"
	default:
		return "invalid_request"
	}
}
