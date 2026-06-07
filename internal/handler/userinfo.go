package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

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
