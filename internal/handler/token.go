package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/server"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/service"
)

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
			status := tokenErr.HTTPStatus
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
			if tokenErr.Code == "invalid_client" {
				c.Header("WWW-Authenticate", `Basic realm="OAuth2"`)
			}
			c.AbortWithStatusJSON(status, model.ErrorResponse{
				Error:            tokenErr.Code,
				ErrorDescription: tokenErr.Description,
			})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		})
		return
	}

	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, resp)
}
