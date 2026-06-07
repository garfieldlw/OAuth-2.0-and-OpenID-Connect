package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

var _ = model.OIDCDiscovery{}

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
