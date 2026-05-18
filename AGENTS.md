# AGENTS.md

## Project Status

**Spec-compliant implementation** — OAuth 2.1 + OIDC server compiles and runs. Native Go implementation (no go-oauth2 dependency). In-memory stores, Swagger docs, authorization code flow with PKCE (S256 only), 4 grant types working. Implicit and hybrid flows removed per OAuth 2.1 security recommendations. Token revocation (RFC 7009) implemented.

## What This Is

Go server implementing OAuth 2.1 + OpenID Connect 1.0 (identity provider / authorization server). Native implementation — no `go-oauth2` dependency. `id_token` is a first-class citizen integrated directly into the token flow.

- **Module**: `github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect`
- **Go version**: 1.25.0
- **Framework**: Gin (`github.com/gin-gonic/gin`)
- **JWT**: `github.com/golang-jwt/jwt/v5` (RS256 signing)
- **JWKS**: `github.com/go-jose/go-jose/v4` (RFC 7638 thumbprint kid)
- **Sessions**: `github.com/go-session/session/v3`
- **API docs**: `github.com/swaggo/swag` + `gin-swagger`
- **License**: MIT
- **Remote**: `github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect`

## Directory Layout

```
cmd/server/main.go → Entrypoint: wires server, routes, session, Swagger UI, rate limiting, RSA key loading
internal/
  handler/handler.go → Gin handlers for all endpoints (Authorize, Token, UserInfo, Revoke, etc.)
  server/
    server.go → Server struct, NewServer(), RegisterClient(), ValidateBearerToken(), RevokeToken(), IsRedirectURIRegistered()
    store.go → ClientStore, AuthCodeStore, TokenStore (sync.Map in-memory)
    token.go → TokenGenerator: JWT RS256 access/id/refresh/code generation + validation
    authorize.go → Authorize(): authorization code flow only (implicit/hybrid removed per OAuth 2.1)
    grant.go → Token(): dispatches by grant_type → authorization_code/password/client_credentials/refresh_token
    pkce.go → VerifyPKCE(): S256-only code verifier validation
  oidc/oidc.go → JWKSBuilder, ComputeKeyID (RFC 7638), DiscoveryBuilder
  model/model.go → User, UserStore, AppConfig, OIDCDiscovery, IDTokenClaims, Swagger models
  service/
    auth_service.go → Login authentication and consent decision logic
    token_service.go → Token endpoint business logic and error mapping
    userinfo_service.go → OIDC UserInfo endpoint business logic (requires openid scope)
  docs/ → Generated Swagger docs (swagger.json, swagger.yaml, docs.go)
  templates/ → HTML templates (login.html, auth.html, error.html)
```

## Architecture

### Core Principle

**No external OAuth2 library.** The server implements OAuth 2.1 and OIDC natively. `id_token` is generated inline within `grant.go` wherever `scope=openid` + user context exists — no `ExtensionFieldsHandler` hacks, no `sync.Map` cross-request state stores, no interceptors.

**Implicit and hybrid flows are removed** per OAuth 2.1 (RFC 9728) security recommendations. Only `response_type=code` (authorization code flow with PKCE) is supported at the authorization endpoint. All tokens (access_token, id_token, refresh_token) are issued exclusively via the token endpoint response body, never exposed in browser URL fragments.

### Server struct (`internal/server/server.go`)

```
Server {
  Clients *ClientStore        // Registered OAuth2 clients
  AuthCodes *AuthCodeStore    // Pending authorization codes
  Tokens *TokenStore          // Active access + refresh tokens
  Generator *TokenGenerator   // JWT RS256 generator (access, id, refresh, code)
  UserStore *model.UserStore  // User identity store
  PasswordAuthFunc func(...)  // Password grant handler (set via SetPasswordAuthHandler)
}
```

### Client struct (`internal/server/store.go`)

```
Client {
  ID                string
  Secret            string
  RedirectURIs      []string
  Scopes            []string
  AllowedGrantTypes []string   // e.g. ["authorization_code", "password", "client_credentials", "refresh_token"]
}
```

`IsGrantTypeAllowed(grantType)` checks if the client is permitted to use a specific grant type. All grant handlers validate this before proceeding.

### Authorization Flow (`internal/server/authorize.go`)

`Server.Authorize(req)` accepts only `response_type=code`:

| response_type | Method | Returns via redirect |
|---|---|---|
| `code` | `authorizeCode()` | `?code=X&state=Y` (query) |

Any other `response_type` returns `unsupported_response_type` with a message about OAuth 2.1 compliance.

Authorization codes store `Nonce`, `ResponseType`, `CodeChallenge`, `CodeChallengeMethod`, `AuthTime` — the code itself carries all context needed for token exchange, replacing any external state store.

PKCE is **required** per OAuth 2.1 (RFC 9728 §7.1) — `code_challenge` must be present and `code_challenge_method` must be `S256`.

### Token Flow (`internal/server/grant.go`)

`Server.Token(req)` dispatches by `grant_type`:

| grant_type | Method | ID Token? | Refresh Token? |
|---|---|---|---|
| `authorization_code` | `grantAuthorizationCode()` | Yes, if `scope` includes `openid` + userID | Yes |
| `password` | `grantPassword()` | Yes, if `scope` includes `openid` | Yes |
| `client_credentials` | `grantClientCredentials()` | Never (no user context) | Never (per RFC 6749 §4.4.3) |
| `refresh_token` | `grantRefreshToken()` | Yes, if `scope` includes `openid` + userID | Yes (rotated) |

Each grant handler validates `client.IsGrantTypeAllowed(grantType)` before processing.

ID token inclusion is decided by `ShouldIncludeIDToken(scope, userID, userStore)` — returns true when `openid` scope present AND userID non-empty AND userStore available.

### Token Revocation (`internal/server/server.go`)

`Server.RevokeToken(token, tokenTypeHint, clientID)` implements RFC 7009:
- Accepts optional `token_type_hint` (`access_token` or `refresh_token`)
- Validates client ownership of the token before revocation
- If no hint provided, tries access token store then refresh token store
- Returns success even if token not found (per RFC 7009 §2.2)
- Revoking a refresh token also deletes its associated access token

### Token Generator (`internal/server/token.go`)

- **Access tokens**: JWT RS256 with `iss`, `sub`, `aud`, `exp`, `iat`, `scope` claims + `kid` header
- **ID tokens**: JWT RS256 with `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, optional `nonce`/`email`/`name`/`email_verified` + `kid` header
- **Refresh tokens**: 32-byte random string (base64url), 24h expiry (checked on retrieval)
- **Authorization codes**: 24-byte random string (base64url), 1-minute expiry, single-use
- **Validation**: `ValidateAccessToken()` parses + verifies RS256 signature + `kid`

### Stores (`internal/server/store.go`)

All in-memory via `sync.Map`. Interface-compatible for future DB backends:

- **ClientStore**: `GetByID()`, `Set()` — registered clients (id, secret, redirect URIs, scopes, allowed grant types)
- **AuthCodeStore**: `Create()`, `Get()`, `Delete()` — 1-minute expiry, single-use (deleted on exchange)
- **TokenStore**: `CreateAccessToken()`, `GetAccessToken()`, `DeleteAccessToken()`, `CreateRefreshToken()`, `GetRefreshToken()`, `DeleteRefreshToken()` — both access and refresh tokens have expiry checks on retrieval; refresh tokens are rotated (old deleted, new created on exchange)

### PKCE (`internal/server/pkce.go`)

`VerifyPKCE(challenge, method, verifier)` — if `challenge` is empty, returns true (PKCE optional at verification time, but required at authorization). Supports `S256` only (SHA-256 + base64url). The `plain` method is removed per OAuth 2.1 security recommendations.

### OIDC Layer (`internal/oidc/oidc.go`)

- **JWKSBuilder**: Builds `jose.JSONWebKeySet` from RSA public key with `kid`, `alg=RS256`, `use=sig`
- **ComputeKeyID**: RFC 7638 JWK thumbprint (SHA-256) → base64url encoded
- **DiscoveryBuilder**: Builds `OIDCDiscovery` struct from `AppConfig` (issuer, endpoints, supported scopes/claims/response types/grant types, revocation and end_session endpoints, response_modes_supported, claims_parameter_supported)

## Endpoints

| Route | Method | Handler | Description |
|---|---|---|---|
| `/api/login` | GET/POST | `Login` | Login API |
| `/api/auth` | GET/POST | `Auth` | Consent/approval API |
| `/oauth/authorize` | GET/POST | `Authorize` | OAuth2/OIDC authorization endpoint (code only) |
| `/oauth/token` | POST | `Token` | OAuth2 token endpoint (rate-limited: 10/min/IP) |
| `/oauth/revoke` | POST | `Revoke` | Token revocation endpoint (RFC 7009) |
| `/userinfo` | GET/POST | `UserInfo` | OIDC UserInfo endpoint (requires openid scope) |
| `/.well-known/openid-configuration` | GET | `Discovery` | OIDC Discovery document |
| `/.well-known/jwks.json` | GET | `JWKS` | JSON Web Key Set |
| `/api/test` | GET | middleware+test | Bearer token verification demo |
| `/logout` | GET | `Logout` | End session (validates post_logout_redirect_uri) |
| `/swagger/*any` | GET | gin-swagger | Swagger UI |

## Key Conventions

- **Native implementation**: No `go-oauth2` dependency. All OAuth2/OIDC logic in `internal/server/`.
- **OAuth 2.1 compliant**: Only authorization code flow with PKCE (S256 only). No implicit or hybrid flows. No `plain` PKCE.
- **id_token is first-class**: Generated inline in grant flows when `scope=openid`, not bolted on via interceptors or extension handlers. Includes `auth_time` and `email_verified` claims.
- **Authorization code carries full context**: `AuthorizationCode` struct stores `Nonce`, `ResponseType`, `CodeChallenge`, `CodeChallengeMethod`, `AuthTime` — no external state stores needed.
- **Client grant type enforcement**: `Client.AllowedGrantTypes []string` controls which grant types each client may use. Checked in every grant handler.
- **Gin handlers**: Use Gin router groups and middleware. Follow Gin idioms (`c.JSON`, `c.AbortWithError`, `ShouldBind`).
- **Session management**: `go-session/session/v3` for login flow (`LoggedInUserID`, `AuthTime` in session).
- **Redirect URI validation**: Exact match against registered URIs. Also validated for `post_logout_redirect_uri` in logout.
- **Refresh token rotation**: Old refresh token + old access token deleted on exchange; new pair created.
- **Refresh token expiry**: Checked on retrieval in `GetRefreshToken()` — expired tokens are deleted and return not found.
- **Rate limiting**: Token endpoint limited to 10 requests/minute per IP.
- **Token revocation**: RFC 7009 compliant — `/oauth/revoke` endpoint, validates client ownership, returns 200 even for unknown tokens.
- **UserInfo scope check**: UserInfo endpoint requires `openid` scope per OIDC Core 1.0 §5.1.
- **Swagger annotations**: Use swag DSL in godoc comments. Regenerate with `/Users/wei/go/bin/swag init -g cmd/server/main.go -o ./docs --parseDependency --parseInternal`.

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `OAUTH_SECURE_COOKIE` | Set to `true` or `1` to enable Secure cookies with SameSite=Strict | `false` (Lax mode) |
| `OAUTH_RSA_KEY_PATH` | Path to PEM-encoded RSA private key file (PKCS1 or PKCS8) | (empty → ephemeral key generated) |
| `OAUTH_SESSION_SECRET` | Session signing secret | `oauth2-session-secret` |

## Demo Configuration

- **Server**: `http://localhost:9096`
- **Clients**: `000000`/`999999` (redirect `http://localhost:9094`, all 4 grant types), `111111`/`11111111` (redirect `http://localhost:9094`, all 4 grant types)
- **Users**: `admin`/`admin` (ID=1), `test`/`test` (ID=2)
- **RSA key**: 2048-bit, generated at startup (or loaded from `OAUTH_RSA_KEY_PATH`)
- **kid**: RFC 7638 JWK thumbprint (SHA-256)

## Known Limitations / Future Work

- **In-memory stores only**: All state lost on restart. Add DB-backed stores (Redis, PostgreSQL, GORM) for production.
- **No dynamic client registration**: Clients hardcoded in `main.go`. Add registration endpoint.
- **No token introspection endpoint**: Add RFC 7662.
- **No encrypted tokens**: Consider `go-jose` for JWE if needed.
- **No tests**: Add unit + integration tests.

## Security-Critical Areas

- Token generation, signing, and validation (RSA-2048 RS256, kid via RFC 7638 thumbprint)
- Authorization code flow — PKCE required (S256 only per OAuth 2.1), code binding, redirect URI strict matching (exact match)
- Constant-time client secret comparison (`subtle.ConstantTimeCompare`)
- Session/cookie handling — httpOnly, SameSite=Lax (dev), Secure+Strict (prod via `OAUTH_SECURE_COOKIE`)
- `auth_time` tracked from login through session → auth code → ID token
- `post_logout_redirect_uri` validation against registered client URIs in logout
- Rate limiting on token endpoint (10 req/min/IP)
- Client secret storage — never log or expose
- Scope validation and enforcement (`openid` scope required for OIDC, required for UserInfo)
- Client grant type enforcement — each grant handler validates `IsGrantTypeAllowed()`
- Token revocation validates client ownership before deleting tokens
- Authorization code 1-minute expiry with single-use (deleted on exchange)
- Refresh token expiry check on retrieval (24h TTL)
- .env file is gitignored — use it for secrets, never commit credentials
