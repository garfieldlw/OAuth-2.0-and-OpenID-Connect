package router

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/handler"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/middleware"
)

type Config struct {
	TokenRateLimit int
	TokenRateWindow time.Duration
	WebDistDir string
}

func DefaultConfig() *Config {
	return &Config{
		TokenRateLimit: 10,
		TokenRateWindow: time.Minute,
		WebDistDir: "./web/dist",
	}
}

func Setup(engine *gin.Engine, h *handler.Handler, cfg *Config) {
	engine.Use(middleware.CORS())
	engine.Use(middleware.Session())

	engine.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/login")
	})

	apiGroup := engine.Group("/api")
	{
		apiGroup.GET("/login", h.Login)
		apiGroup.POST("/login", h.Login)
		apiGroup.GET("/auth", h.Auth)
		apiGroup.POST("/auth", h.Auth)
	}

	oauth := engine.Group("/oauth")
	{
		oauth.GET("/authorize", h.Authorize)
		oauth.POST("/authorize", h.Authorize)
		oauth.POST("/token", middleware.RateLimit(cfg.TokenRateLimit, cfg.TokenRateWindow), h.Token)
		oauth.POST("/revoke", h.Revoke)
	}

	engine.GET("/userinfo", h.UserInfo)
	engine.POST("/userinfo", h.UserInfo)

	engine.GET("/.well-known/openid-configuration", h.Discovery)
	engine.GET("/.well-known/jwks.json", h.JWKS)

	apiTest := engine.Group("/api/test")
	{
		apiTest.Use(h.HandleTokenVerify)
		apiTest.GET("", h.TokenTest)
	}

	engine.GET("/logout", h.Logout)

	engine.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	if cfg.WebDistDir != "" {
		engine.Static("/assets", cfg.WebDistDir+"/assets")
		engine.NoRoute(func(c *gin.Context) {
			c.File(cfg.WebDistDir + "/index.html")
		})
	}
}
