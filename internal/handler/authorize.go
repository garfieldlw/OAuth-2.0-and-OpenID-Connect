package handler

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/server"
)

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
		AuthTime:            sessionData.AuthTime,
	}

	result, err := h.Server.Authorize(req)
	if err != nil {
		var authErr *server.AuthorizeError
		if errors.As(err, &authErr) {
			if authErr.RedirectURI != "" {
				redirectURL, parseErr := url.Parse(authErr.RedirectURI)
				if parseErr == nil {
					q := redirectURL.Query()
					q.Set("error", authErr.Code)
					q.Set("error_description", authErr.Description)
					if authErr.State != "" {
						q.Set("state", authErr.State)
					}
					redirectURL.RawQuery = q.Encode()
					c.Redirect(http.StatusFound, redirectURL.String())
					return
				}
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, model.ErrorResponse{
				Error: authErr.Code, ErrorDescription: authErr.Description,
			})
			return
		}
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
