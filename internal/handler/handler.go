package handler

import (
	"encoding/base64"
	"strings"

	"github.com/go-session/session/v3"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/oidc"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/server"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/service"
)

type Handler struct {
	Server           *server.Server
	DiscoveryBuilder *oidc.DiscoveryBuilder
	JWKSBuilder      *oidc.JWKSBuilder
	UserStore        *model.UserStore
	Config           *model.AppConfig
	AuthService      *service.AuthService
	UserInfoService  *service.UserInfoService
	TokenService     *service.TokenService
}

func NewHandler(srv *server.Server, discovery *oidc.DiscoveryBuilder, jwks *oidc.JWKSBuilder, userStore *model.UserStore, config *model.AppConfig, authSvc *service.AuthService, userInfoSvc *service.UserInfoService, tokenSvc *service.TokenService) *Handler {
	return &Handler{
		Server:           srv,
		DiscoveryBuilder: discovery,
		JWKSBuilder:      jwks,
		UserStore:        userStore,
		Config:           config,
		AuthService:      authSvc,
		UserInfoService:  userInfoSvc,
		TokenService:     tokenSvc,
	}
}

// parseBasicAuth extracts client_id and client_secret from the Authorization header
// per RFC 6749 §2.3.1. The header format is:
//
//	Authorization: Basic base64(client_id:client_secret)
//
// Returns empty strings if the header is absent or malformed.
func parseBasicAuth(authHeader string) (clientID, clientSecret string) {
	if authHeader == "" {
		return "", ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return "", ""
	}

	payload, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		// Try URL-safe base64 as some clients use it
		payload, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			// Try standard base64 with padding
			payload, err = base64.StdEncoding.DecodeString(strings.TrimRight(parts[1], "="))
			if err != nil {
				return "", ""
			}
		}
	}

	decoded := string(payload)
	idx := strings.IndexByte(decoded, ':')
	if idx < 0 {
		return "", ""
	}

	return decoded[:idx], decoded[idx+1:]
}

func (h *Handler) readSessionData(sess session.Store) *service.SessionData {
	val, _ := sess.Get("LoggedInUserID")
	userID, _ := val.(string)

	rv, _ := sess.Get("ReturnURI")
	returnURI, _ := rv.(string)

	var authTime int64
	at, _ := sess.Get("AuthTime")
	if atVal, ok := at.(int64); ok {
		authTime = atVal
	} else if atFloat, ok := at.(float64); ok {
		authTime = int64(atFloat)
	}

	return &service.SessionData{
		LoggedInUserID: userID,
		ReturnURI:      returnURI,
		AuthTime:       authTime,
	}
}
