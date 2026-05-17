package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/oidc"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/server"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/service"
)

type Handler struct {
	Server          *server.Server
	DiscoveryBuilder *oidc.DiscoveryBuilder
	JWKSBuilder     *oidc.JWKSBuilder
	UserStore       *model.UserStore
	Config          *model.AppConfig
	AuthService     *service.AuthService
	UserInfoService *service.UserInfoService
	TokenService    *service.TokenService
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

// LoginStatus godoc
// @Summary Check login status
// @Description Returns whether the current session has an authenticated user. If logged in, also returns the redirect URI stored in the session.
// @Tags Auth
// @Produce json
// @Success 200 {object} model.LoginStatusResponse
// @Router /api/login [get]
// Login godoc
// @Summary Authenticate user
// @Description Authenticates a user with username and password. Creates a server-side session and returns a redirect URI (either the stored ReturnURI from a prior authorize attempt, or /auth).
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body model.LoginRequest true "Login credentials"
// @Success 200 {object} model.LoginResponse
// @Failure 400 {object} model.ErrorResponse
// @Failure 401 {object} model.ErrorResponse
// @Router /api/login [post]
func (h *Handler) Login(c *gin.Context) {
	sess, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Error: "server_error", ErrorDescription: "session error"})
		return
	}

	if c.Request.Method == http.MethodGet {
		sessionData := h.readSessionData(sess)
		loggedIn, redirect := h.AuthService.GetLoginStatus(sessionData)
		if loggedIn {
			c.JSON(http.StatusOK, model.LoginStatusResponse{LoggedIn: true, Redirect: redirect})
			return
		}
		c.JSON(http.StatusOK, model.LoginStatusResponse{LoggedIn: false})
		return
	}

	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Error: "invalid_request", ErrorDescription: "username and password required"})
		return
	}

	userID, ok := h.AuthService.Authenticate(req.Username, req.Password)
	if !ok {
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: "invalid_credentials", ErrorDescription: "Invalid username or password"})
		return
	}

	sess.Set("LoggedInUserID", userID)
	sess.Set("LoggedInUsername", req.Username)
	sess.Save()

	sessionData := h.readSessionData(sess)
	redirect := h.AuthService.GetLoginRedirect(sessionData)
	c.JSON(http.StatusOK, model.LoginResponse{Redirect: redirect})
}

// AuthContext godoc
// @Summary Get authorization context
// @Description Returns the consent page context for the current authorization request, including the logged-in user ID, client ID, and requested scope. Requires an active user session.
// @Tags Auth
// @Produce json
// @Param client_id query string false "Client identifier from the authorize request"
// @Param scope query string false "Space-delimited scopes from the authorize request"
// @Success 200 {object} model.AuthContextResponse
// @Failure 401 {object} model.ErrorResponse
// @Router /api/auth [get]
// AuthDecision godoc
// @Summary Submit authorization decision
// @Description Submits the user's consent decision (approve or deny) for the current authorization request. On approval, returns the stored ReturnURI (the original /oauth/authorize URL) so the frontend can redirect the browser. On denial, returns a redirect URI with error=access_denied.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body model.AuthDecisionRequest true "Authorization decision"
// @Success 200 {object} model.AuthDecisionResponse
// @Failure 400 {object} model.ErrorResponse
// @Failure 401 {object} model.ErrorResponse
// @Router /api/auth [post]
func (h *Handler) Auth(c *gin.Context) {
	sess, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.ErrorResponse{Error: "server_error", ErrorDescription: "session error"})
		return
	}

	sessionData := h.readSessionData(sess)
	if sessionData.LoggedInUserID == "" {
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: "unauthorized", ErrorDescription: "Not logged in"})
		return
	}

	if c.Request.Method == http.MethodGet {
		c.JSON(http.StatusOK, model.AuthContextResponse{
			UserID:   sessionData.LoggedInUserID,
			ClientID: c.Query("client_id"),
			Scope:    c.Query("scope"),
		})
		return
	}

	var req model.AuthDecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Error: "invalid_request", ErrorDescription: "invalid request body"})
		return
	}

	redirect, svcErr := h.AuthService.ProcessAuthDecision(sessionData, req.Authorize, req.Deny)
	if svcErr != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{Error: "invalid_request", ErrorDescription: svcErr.Error()})
		return
	}
	c.JSON(http.StatusOK, model.AuthDecisionResponse{Redirect: redirect})
}

// Authorize godoc
// @Summary OAuth 2.0 / OIDC Authorization Endpoint
// @Description Authenticates the resource owner and issues an authorization code. Requires an active user session. Implicit and hybrid flows are removed per OAuth 2.1 security recommendations.
// @Tags OAuth2
// @Accept json,application/x-www-form-urlencoded
// @Produce json
// @Param response_type query string true "Response type" Enums(code)
// @Param client_id query string true "Client identifier"
// @Param redirect_uri query string true "Redirect URI registered for the client"
// @Param scope query string false "Space-delimited scopes (e.g. openid profile email)"
// @Param state query string false "Opaque value returned to the client"
// @Param nonce query string false "Nonce for ID token replay protection (recommended when scope includes openid)"
// @Param code_challenge query string false "PKCE code challenge"
// @Param code_challenge_method query string false "PKCE method" Enums(S256)
// @Success 302 {string} string "Redirect to redirect_uri with authorization code in query"
// @Failure 400 {object} model.ErrorResponse
// @Failure 401 {object} model.ErrorResponse
// @Router /oauth/authorize [get]
// @Router /oauth/authorize [post]
func (h *Handler) Authorize(c *gin.Context) {
	sess, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	sessionData := h.readSessionData(sess)
	userID, needsLogin := h.AuthService.GetAuthorizeSessionCheck(sessionData)
	if needsLogin {
		sess.Set("ReturnURI", c.Request.RequestURI)
		sess.Save()
		c.Redirect(http.StatusFound, "/login")
		return
	}

	req := &server.AuthorizeRequest{
		ResponseType:        c.Query("response_type"),
		ClientID:            c.Query("client_id"),
		RedirectURI:         c.Query("redirect_uri"),
		Scope:               c.Query("scope"),
		State:               c.Query("state"),
		Nonce:               c.Query("nonce"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
		UserID:              userID,
	}

	result, err := h.Server.Authorize(req)
	if err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	redirectURL, parseErr := url.Parse(result.RedirectURI)
	if parseErr != nil {
		c.AbortWithError(http.StatusBadRequest, parseErr)
		return
	}
	q := redirectURL.Query()
	q.Set("code", result.Code)
	if result.State != "" {
		q.Set("state", result.State)
	}
	redirectURL.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, redirectURL.String())
}

// Token godoc
// @Summary OAuth 2.0 Token Endpoint
// @Description Issues tokens based on the grant type. Supports authorization_code, password, client_credentials, and refresh_token grants. Returns id_token when scope includes openid and a user context exists. Client authentication via Authorization header (client_secret_basic) takes precedence over body params (client_secret_post) per RFC 6749 §2.3.1.
// @Tags OAuth2
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param Authorization header string false "Client credentials via HTTP Basic: Basic base64(client_id:client_secret)"
// @Param grant_type formData string true "Grant type" Enums(authorization_code, password, client_credentials, refresh_token)
// @Param client_id formData string false "Client identifier (required if not using Authorization header)"
// @Param client_secret formData string false "Client secret (required if not using Authorization header)"
// @Param code formData string false "Authorization code (authorization_code grant)"
// @Param redirect_uri formData string false "Redirect URI (authorization_code grant)"
// @Param scope formData string false "Space-delimited scopes"
// @Param username formData string false "Username (password grant)"
// @Param password formData string false "Password (password grant)"
// @Param refresh_token formData string false "Refresh token (refresh_token grant)"
// @Param code_verifier formData string false "PKCE code verifier"
// @Success 200 {object} model.TokenResponse
// @Failure 400 {object} model.ErrorResponse
// @Failure 401 {object} model.ErrorResponse
// @Failure 500 {object} model.ErrorResponse
// @Router /oauth/token [post]
// @Router /oauth/token [get]
func (h *Handler) Token(c *gin.Context) {
	// Per RFC 6749 §2.3.1: client credentials via Authorization header take precedence
	headerClientID, headerClientSecret := parseBasicAuth(c.GetHeader("Authorization"))

	bodyClientID := c.PostForm("client_id")
	bodyClientSecret := c.PostForm("client_secret")

	var clientID, clientSecret string
	if headerClientID != "" {
		clientID = headerClientID
		clientSecret = headerClientSecret
		if bodyClientID != "" && bodyClientID != headerClientID {
			c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{
				Error:            "invalid_client",
				ErrorDescription: "conflicting client_id in Authorization header and request body",
			})
			return
		}
	} else {
		clientID = bodyClientID
		clientSecret = bodyClientSecret
	}

	if clientID == "" {
		clientID = c.Query("client_id")
	}
	if clientSecret == "" {
		clientSecret = c.Query("client_secret")
	}

	req := &server.TokenRequest{
		GrantType:    c.PostForm("grant_type"),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         c.PostForm("code"),
		RedirectURI:  c.PostForm("redirect_uri"),
		Scope:        c.PostForm("scope"),
		Username:     c.PostForm("username"),
		Password:     c.PostForm("password"),
		RefreshToken: c.PostForm("refresh_token"),
		CodeVerifier: c.PostForm("code_verifier"),
	}

	if req.GrantType == "" {
		req.GrantType = c.Query("grant_type")
	}
	if req.Code == "" {
		req.Code = c.Query("code")
	}
	if req.RedirectURI == "" {
		req.RedirectURI = c.Query("redirect_uri")
	}
	if req.Scope == "" {
		req.Scope = c.Query("scope")
	}
	if req.Username == "" {
		req.Username = c.Query("username")
	}
	if req.Password == "" {
		req.Password = c.Query("password")
	}
	if req.RefreshToken == "" {
		req.RefreshToken = c.Query("refresh_token")
	}
	if req.CodeVerifier == "" {
		req.CodeVerifier = c.Query("code_verifier")
	}

	resp, err := h.TokenService.ProcessToken(req)
	if err != nil {
		var tokenErr *service.TokenError
		if errors.As(err, &tokenErr) {
			c.AbortWithStatusJSON(tokenErr.HTTPStatus, model.ErrorResponse{
				Error:             tokenErr.Code,
				ErrorDescription: tokenErr.Description,
			})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ErrorResponse{
			Error:             "invalid_request",
			ErrorDescription:  err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// UserInfo godoc
// @Summary OIDC UserInfo Endpoint
// @Description Returns claims about the authenticated end-user. Requires a valid Bearer access token with openid scope.
// @Tags OIDC
// @Accept json,application/x-www-form-urlencoded
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Success 200 {object} model.UserInfoResponse
// @Failure 401 {object} model.ErrorResponse
// @Failure 404 {object} model.ErrorResponse
// @Router /userinfo [get]
// @Router /userinfo [post]
func (h *Handler) UserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: "invalid_token", ErrorDescription: "Authorization header required"})
		return
	}

	result, err := h.UserInfoService.GetUserInfo(authHeader)
	if err != nil {
		if err.Error() == "user_not_found: user not found" {
			c.JSON(http.StatusNotFound, model.ErrorResponse{Error: "user_not_found", ErrorDescription: "user not found"})
			return
		}
		c.JSON(http.StatusUnauthorized, model.ErrorResponse{Error: "invalid_token", ErrorDescription: err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// Discovery godoc
// @Summary OIDC Discovery Document
// @Description Returns the OpenID Provider Configuration Information as specified in OpenID Connect Discovery 1.0.
// @Tags OIDC
// @Produce json
// @Success 200 {object} model.OIDCDiscovery
// @Router /.well-known/openid-configuration [get]
func (h *Handler) Discovery(c *gin.Context) {
	c.JSON(http.StatusOK, h.DiscoveryBuilder.Build())
}

// JWKS godoc
// @Summary JSON Web Key Set
// @Description Returns the server's public RSA key in JWK format used to verify JWT signatures (RS256). Cacheable for 3600 seconds.
// @Tags OIDC
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /.well-known/jwks.json [get]
func (h *Handler) JWKS(c *gin.Context) {
	jwks := h.JWKSBuilder.Build()
	c.JSON(http.StatusOK, jwks)
	c.Header("Cache-Control", "public, max-age=3600")
	c.Header("Access-Control-Allow-Origin", "*")
}

// HandleTokenVerify godoc
// @Summary Bearer Token Verification Middleware
// @Description Validates the Bearer access token from the Authorization header. Sets TokenInfo in the Gin context on success.
// @Tags API
// @Produce json
// @Param Authorization header string true "Bearer access token"
// @Success 200 {string} string "Token valid, TokenInfo set in context"
// @Failure 401 {object} model.ErrorResponse
// @Router /api/test [get]
func (h *Handler) HandleTokenVerify(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{Error: "invalid_token", ErrorDescription: "Authorization header required"})
		return
	}

	ti, err := h.TokenService.ValidateBearer(authHeader)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{Error: "invalid_token", ErrorDescription: err.Error()})
		return
	}
	c.Set("TokenInfo", ti)
	c.Next()
}

// TokenTest returns the TokenInfo set by HandleTokenVerify middleware.
func (h *Handler) TokenTest(c *gin.Context) {
	ti, exists := c.Get("TokenInfo")
	if exists {
		c.JSON(http.StatusOK, ti)
		return
	}
	c.String(http.StatusOK, "not found")
}

// Logout godoc
// @Summary End Session
// @Description Ends the user session and redirects to the login page or the post_logout_redirect_uri.
// @Tags OAuth2
// @Produce json
// @Param post_logout_redirect_uri query string false "URI to redirect after logout"
// @Success 302 {string} string "Redirect to login or post_logout_redirect_uri"
// @Router /logout [get]
func (h *Handler) Logout(c *gin.Context) {
	sess, err := session.Start(c.Request.Context(), c.Writer, c.Request)
	if err == nil {
		keys := h.AuthService.ProcessLogout()
		for _, key := range keys {
			sess.Delete(key)
		}
		sess.Save()
	}
	redirect := c.Query("post_logout_redirect_uri")
	if redirect != "" {
		c.Redirect(http.StatusFound, redirect)
		return
	}
	c.Redirect(http.StatusFound, "/login")
}

func (h *Handler) SetupPasswordAuth() {
	h.Server.SetPasswordAuthHandler(func(ctx context.Context, clientID, username, password string) (string, error) {
		userID, ok := h.AuthService.Authenticate(username, password)
		if !ok {
			return "", fmt.Errorf("invalid credentials")
		}
		return userID, nil
	})
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

	return &service.SessionData{
		LoggedInUserID: userID,
		ReturnURI:      returnURI,
	}
}
