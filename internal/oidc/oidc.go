package oidc

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

type JWKSBuilder struct {
	publicKey *rsa.PublicKey
	keyID     string
}

func NewJWKSBuilder(publicKey *rsa.PublicKey, keyID string) *JWKSBuilder {
	return &JWKSBuilder{
		publicKey: publicKey,
		keyID:     keyID,
	}
}

func (b *JWKSBuilder) Build() jose.JSONWebKeySet {
	jwk := jose.JSONWebKey{
		Key:       b.publicKey,
		KeyID:     b.keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}
}

func ComputeKeyID(pubKey *rsa.PublicKey) string {
	jwk := jose.JSONWebKey{
		Key:       pubKey,
		Algorithm: "RS256",
		Use:       "sig",
	}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return base64.RawURLEncoding.EncodeToString([]byte("fallback-kid"))
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint)
}

type DiscoveryBuilder struct {
	config *model.AppConfig
}

func NewDiscoveryBuilder(config *model.AppConfig) *DiscoveryBuilder {
	return &DiscoveryBuilder{config: config}
}

func (b *DiscoveryBuilder) Build() *model.OIDCDiscovery {
	baseURL := b.config.Issuer
	return &model.OIDCDiscovery{
		Issuer:                            baseURL,
		AuthorizationEndpoint:             fmt.Sprintf("%s/oauth/authorize", baseURL),
		TokenEndpoint:                     fmt.Sprintf("%s/oauth/token", baseURL),
		UserInfoEndpoint:                  fmt.Sprintf("%s/userinfo", baseURL),
		JWKSETEndpoint:                    fmt.Sprintf("%s/.well-known/jwks.json", baseURL),
		EndSessionEndpoint:                fmt.Sprintf("%s/logout", baseURL),
		RevocationEndpoint:                fmt.Sprintf("%s/oauth/revoke", baseURL),
		ScopesSupported:                   []string{"openid", "profile", "email"},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials", "refresh_token", "password"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "email", "email_verified"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsParameterSupported:          false,
	}
}
