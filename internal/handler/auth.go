package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

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
