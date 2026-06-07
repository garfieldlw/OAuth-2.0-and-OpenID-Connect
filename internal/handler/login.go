package handler

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

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
	sess.Set("AuthTime", time.Now().Unix())
	sess.Save()

	sessionData := h.readSessionData(sess)
	redirect := h.AuthService.GetLoginRedirect(sessionData)
	c.JSON(http.StatusOK, model.LoginResponse{Redirect: redirect})
}
