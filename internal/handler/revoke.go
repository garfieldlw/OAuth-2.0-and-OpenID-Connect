package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/server"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/service"
)

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
// @Description Ends the user session and redirects to the login page or the post_logout_redirect_uri. Per OIDC Session Management 1.0, post_logout_redirect_uri must match a client's registered redirect URI.
// @Tags OAuth2
// @Produce json
// @Param post_logout_redirect_uri query string false "URI to redirect after logout (must match a client's registered redirect URI)"
// @Param client_id query string false "Client identifier (recommended when using post_logout_redirect_uri)"
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
		// Per OIDC Session Management: validate post_logout_redirect_uri
		// against client's registered redirect URIs
		clientID := c.Query("client_id")
		if !h.Server.IsRedirectURIRegistered(clientID, redirect) {
			c.Redirect(http.StatusFound, "/login")
			return
		}
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

// Revoke godoc
// @Summary OAuth 2.0 Token Revocation Endpoint
// @Description Revokes an access token or refresh token per RFC 7009. The token_type_hint parameter is optional but recommended. If the token is not found, the endpoint still returns 200 per RFC 7009 §2.2.
// @Tags OAuth2
// @Accept application/x-www-form-urlencoded
// @Param Authorization header string false "Client credentials via HTTP Basic: Basic base64(client_id:client_secret)"
// @Param client_id formData string false "Client identifier (required if not using Authorization header)"
// @Param client_secret formData string false "Client secret (required if not using Authorization header)"
// @Param token formData string true "The token to revoke"
// @Param token_type_hint formData string false "Hint about the type of token: access_token or refresh_token" Enums(access_token, refresh_token)
// @Success 200 {string} string "Token revoked or not found (both return 200 per RFC 7009)"
// @Failure 401 {object} model.ErrorResponse
// @Router /oauth/revoke [post]
func (h *Handler) Revoke(c *gin.Context) {
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

	if !h.Server.ValidateClient(clientID, clientSecret) {
		c.Header("WWW-Authenticate", `Basic realm="OAuth2"`)
		c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "client authentication failed",
		})
		return
	}

	token := c.PostForm("token")
	if token == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "token parameter is required",
		})
		return
	}

	tokenTypeHint := c.PostForm("token_type_hint")

	err := h.Server.RevokeToken(token, tokenTypeHint, clientID)
	if err != nil {
		var oauthErr *server.OAuthError
		if errors.As(err, &oauthErr) {
			if oauthErr.Code == "invalid_client" {
				c.Header("WWW-Authenticate", `Basic realm="OAuth2"`)
				c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{
					Error:            oauthErr.Code,
					ErrorDescription: oauthErr.Description,
				})
				return
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, model.ErrorResponse{
				Error:            oauthErr.Code,
				ErrorDescription: oauthErr.Description,
			})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ErrorResponse{
			Error:            service.ExtractOAuthError(err.Error()),
			ErrorDescription: err.Error(),
		})
		return
	}

	c.Status(http.StatusOK)
}
