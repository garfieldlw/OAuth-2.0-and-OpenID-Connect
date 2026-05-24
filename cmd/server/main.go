package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"

	docs "github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/docs"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/handler"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/oidc"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/router"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/server"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/service"
)

// @title OAuth 2.0 + OpenID Connect Server
// @version 1.0
// @description Go implementation of OAuth 2.0 Authorization Server and OpenID Connect 1.0 Provider.
// @description Supports authorization code (with PKCE), password, client_credentials, and refresh_token grants per OAuth 2.1.
// @description Implicit and hybrid flows are removed per OAuth 2.1 security recommendations.
// @description Issues JWT access tokens and ID tokens signed with RS256. Provides JWKS and OIDC Discovery endpoints.
// @host localhost:9096
// @BasePath /
// @securitydefinitions.oauth2.authorizationCode OAuth2 Authorization Code
// @tokenurl /oauth/token
// @authorizationurl /oauth/authorize
// @scope.openid Grants access to OpenID Connect ID tokens
// @scope.profile Grants access to user profile claims
// @scope.email Grants access to user email claims
func main() {
	config := model.DefaultAppConfig()

	if secure := os.Getenv("OAUTH_SECURE_COOKIE"); secure == "true" || secure == "1" {
		config.SecureCookie = true
	}

	if keyPath := os.Getenv("OAUTH_RSA_KEY_PATH"); keyPath != "" {
		config.RSAKeyPath = keyPath
	}

	docs.SwaggerInfo.Title = "OAuth 2.0 + OpenID Connect Server"
	docs.SwaggerInfo.Description = "Go implementation of OAuth 2.0 Authorization Server and OpenID Connect 1.0 Provider.\nSupports authorization code (with PKCE), password, client_credentials, and refresh_token grants per OAuth 2.1.\nImplicit and hybrid flows are removed per OAuth 2.1 security recommendations.\nIssues JWT access tokens and ID tokens signed with RS256. Provides JWKS and OIDC Discovery endpoints."
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Host = "localhost:9096"
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Schemes = []string{"http"}

	var privateKey *rsa.PrivateKey
	var err error

	if config.RSAKeyPath != "" {
		privateKey, err = loadRSAKeyFromFile(config.RSAKeyPath)
		if err != nil {
			log.Fatalf("Failed to load RSA key from %s: %v", config.RSAKeyPath, err)
		}
		log.Printf("Loaded RSA key from file: %s", config.RSAKeyPath)
	} else {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate RSA key pair: %v", err)
		}
		log.Printf("Generated ephemeral RSA key (will be lost on restart)")
	}

	config.RSAPrivateKey = privateKey
	config.RSAPublicKey = &privateKey.PublicKey
	config.KeyID = oidc.ComputeKeyID(config.RSAPublicKey)

	sameSite := http.SameSiteLaxMode
	if config.SecureCookie {
		sameSite = http.SameSiteStrictMode
	}

	sessionSecret := os.Getenv("OAUTH_SESSION_SECRET")
	if sessionSecret == "" {
		sessionSecret = "oauth2-session-secret"
	}

	session.InitManager(
		session.SetSign([]byte(sessionSecret)),
		session.SetCookieName("oauth2_session"),
		session.SetCookieLifeTime(3600),
		session.SetSecure(config.SecureCookie),
		session.SetSameSite(sameSite),
	)

	userStore := model.NewUserStore()
	srv := server.NewServer(config, userStore)

	srv.RegisterClient("000000", "999999", []string{"http://localhost:9094"}, []string{"openid", "profile", "email"}, []string{"authorization_code", "password", "client_credentials", "refresh_token"})
	srv.RegisterClient("111111", "11111111", []string{"http://localhost:9094"}, []string{"openid", "profile", "email"}, []string{"authorization_code", "password", "client_credentials", "refresh_token"})

	discovery := oidc.NewDiscoveryBuilder(config)
	jwksBuilder := oidc.NewJWKSBuilder(config.RSAPublicKey, config.KeyID)

	authSvc := service.NewAuthService(userStore)
	userInfoSvc := service.NewUserInfoService(srv, userStore)
	tokenSvc := service.NewTokenService(srv)

	h := handler.NewHandler(srv, discovery, jwksBuilder, userStore, config, authSvc, userInfoSvc, tokenSvc)
	h.SetupPasswordAuth()

	g := gin.New()
	g.Use(gin.Recovery())
	routerCfg := router.DefaultConfig()
	router.Setup(g, h, routerCfg)

	log.Printf("OAuth2 + OIDC Server running at %s", config.Issuer)
	log.Printf("Authorization endpoint: %s/oauth/authorize", config.Issuer)
	log.Printf("Token endpoint: %s/oauth/token", config.Issuer)
	log.Printf("Discovery: %s/.well-known/openid-configuration", config.Issuer)
	log.Printf("JWKS: %s/.well-known/jwks.json", config.Issuer)
	log.Fatal(g.Run(":9096"))
}

func loadRSAKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return rsaKey, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA key (tried PKCS1 and PKCS8): %v", err)
	}
	parsed, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS8 key is not RSA")
	}
	return parsed, nil
}
