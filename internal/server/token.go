package server

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

type TokenGenerator struct {
	Issuer        string
	PrivateKey    *rsa.PrivateKey
	KeyID         string
	SigningMethod jwt.SigningMethod
	AccessExpiry  time.Duration
	IDTokenExpiry time.Duration
	RefreshExpiry time.Duration
}

func NewTokenGenerator(issuer string, privateKey *rsa.PrivateKey, keyID string, signingMethod jwt.SigningMethod) *TokenGenerator {
	return &TokenGenerator{
		Issuer:        issuer,
		PrivateKey:    privateKey,
		KeyID:         keyID,
		SigningMethod: signingMethod,
		AccessExpiry:  2 * time.Hour,
		IDTokenExpiry: 1 * time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}
}

func (g *TokenGenerator) GenerateAccessToken(clientID, userID, scope string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(g.AccessExpiry)
	claims := jwt.MapClaims{
		"iss":   g.Issuer,
		"sub":   userID,
		"aud":   clientID,
		"exp":   expiresAt.Unix(),
		"iat":   now.Unix(),
		"scope": scope,
	}
	token := jwt.NewWithClaims(g.SigningMethod, claims)
	if g.KeyID != "" {
		token.Header["kid"] = g.KeyID
	}
	signed, err := token.SignedString(g.PrivateKey)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func (g *TokenGenerator) GenerateIDToken(clientID, userID, nonce string, user *model.User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       g.Issuer,
		"sub":       userID,
		"aud":       clientID,
		"exp":       now.Add(g.IDTokenExpiry).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if user != nil {
		if user.Email != "" {
			claims["email"] = user.Email
		}
		if user.Name != "" {
			claims["name"] = user.Name
		}
	}
	token := jwt.NewWithClaims(g.SigningMethod, claims)
	if g.KeyID != "" {
		token.Header["kid"] = g.KeyID
	}
	return token.SignedString(g.PrivateKey)
}

func (g *TokenGenerator) GenerateRefreshToken() string {
	return generateRandomString(32)
}

func (g *TokenGenerator) GenerateAuthorizationCode() string {
	return generateRandomString(24)
}

func (g *TokenGenerator) ValidateAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return &g.PrivateKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{g.SigningMethod.Alg()}))
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}

func (g *TokenGenerator) RefreshExpiryTime() time.Time {
	return time.Now().Add(g.RefreshExpiry)
}
