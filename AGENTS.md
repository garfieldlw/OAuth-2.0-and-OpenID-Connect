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
cmd/server/main.go → Entrypoint: wires server, routes, session, Swagger UI, rate limiting, RSA key loading; defers srv.Close()
internal/
handler/
handler.go → Handler struct, NewHandler(), parseBasicAuth(), readSessionData() (shared helpers)
login.go → Login handler (GET/POST /api/login)
auth.go → Auth handler (GET/POST /api/auth — consent decision)
authorize.go → Authorize handler (GET/POST /oauth/authorize)
token.go → Token handler (POST /oauth/token)
revoke.go → Revoke handler (POST /oauth/revoke)
userinfo.go → UserInfo handler (GET/POST /userinfo)
discovery.go → Discovery + JWKS handlers (/.well-known/*)
server/
server.go → Server struct, NewServer(), RegisterClient(), ValidateClient(), ValidateBearerToken(), RevokeToken(), IsRedirectURIRegistered(), Close()
store.go → ClientStore, AuthCodeStore, TokenStore (sync.Map in-memory with background cleanup goroutines)
token.go → TokenGenerator: JWT RS256 access/id/refresh/code generation + validation (all return errors)
authorize.go → Authorize(): authorization code flow only (implicit/hybrid removed per OAuth 2.1); AuthorizeError embeds *OAuthError
grant.go → Token(): dispatches by grant_type; validateAndAuthenticate() + issueTokenPair() helpers
pkce.go → VerifyPKCE(): S256-only code verifier validation (constant-time comparison via subtle.ConstantTimeCompare)
errors.go → OAuthError struct + 8 constructor functions (ErrInvalidClient, ErrInvalidGrant, etc.)
model/model.go → User, UserStore (dual-index + RWMutex + bcrypt), AppConfig, OIDCDiscovery, Swagger request/response models
service/
auth_service.go → Login authentication (bcrypt) and consent decision logic; ExtractOAuthError() fallback
token_service.go → Token endpoint business logic and error mapping (errors.As + TokenError)
userinfo_service.go → OIDC UserInfo endpoint business logic (requires openid scope)
middleware/middleware.go → CORS, session, rate-limit (maxVisitors cap + cleanupLocked), request logger (sensitive key redaction)
router/router.go → Route definitions and middleware wiring
oidc/oidc.go → JWKSBuilder, ComputeKeyID (RFC 7638), DiscoveryBuilder
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
Clients *ClientStore // Registered OAuth2 clients
AuthCodes *AuthCodeStore // Pending authorization codes
Tokens *TokenStore // Active access + refresh tokens
Generator *TokenGenerator // JWT RS256 generator (access, id, refresh, code)
UserStore *model.UserStore // User identity store
PasswordAuthFunc func(ctx context.Context, clientID, username, password string) (string, error)
}
```

`Server.Close()` stops background cleanup goroutines for `AuthCodeStore` and `TokenStore`. Called via `defer srv.Close()` in `main.go`.

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
- **AuthCodeStore**: `Create()`, `Get()`, `Delete()` — 1-minute expiry, single-use (deleted on exchange); background cleanup goroutine with `stopCh` channel, stopped via `Close()`
- **TokenStore**: `CreateAccessToken()`, `GetAccessToken()`, `DeleteAccessToken()`, `CreateRefreshToken()`, `GetRefreshToken()`, `DeleteRefreshToken()` — both access and refresh tokens have expiry checks on retrieval; refresh tokens are rotated (old deleted, new created on exchange); background cleanup goroutine with `stopCh` channel, stopped via `Close()`

`generateRandomString(byteLen int) (string, error)` — uses `crypto/rand` and propagates errors (returns `server_error` wrapped error on failure).

### PKCE (`internal/server/pkce.go`)

`VerifyPKCE(challenge, method, verifier)` — if `challenge` is empty, returns true (PKCE optional at verification time, but required at authorization). Supports `S256` only (SHA-256 + base64url). The `plain` method is removed per OAuth 2.1 security recommendations. S256 comparison uses `subtle.ConstantTimeCompare` to prevent timing attacks.

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

## Development Commands

```bash
# Run the server (starts at http://localhost:9096)
go run cmd/server/main.go

# Build binary
go build -o bin/server cmd/server/main.go

# Run tests (currently no tests exist — see Known Limitations)
go test ./... -v

# Run tests for a specific package
go test ./internal/server/... -v
go test ./internal/service/... -v

# Tidy dependencies
go mod tidy

# Regenerate Swagger docs (MUST run after changing any swag annotations in godoc comments)
/Users/wei/go/bin/swag init -g cmd/server/main.go -o ./docs --parseDependency --parseInternal

# Format code (ALWAYS run before committing)
gofmt -w .

# Vet code (static analysis for common mistakes)
go vet ./...

# Run linter (if golangci-lint is installed)
golangci-lint run ./...

# Generate RSA key for production use
openssl genrsa -out private.pem 2048

# Run with custom RSA key
OAUTH_RSA_KEY_PATH=./private.pem go run cmd/server/main.go

# Run with production cookie settings
OAUTH_SECURE_COOKIE=true OAUTH_SESSION_SECRET=your-secret go run cmd/server/main.go

# Frontend (optional React UI)
cd web && npm install && npm run dev    # Dev server at http://localhost:5173
cd web && npm run build                  # Production build to web/dist/
```

### Build Verification Checklist

After making code changes, ALWAYS verify:

1. `go build ./...` — compiles without errors
2. `go vet ./...` — no vet warnings
3. `gofmt -l .` — no unformatted files (output should be empty)
4. If Swagger annotations were modified: re-run `swag init` and check `docs/` regenerated
5. `go test ./...` — all tests pass (when tests exist)

## Coding Conventions

### Project Structure

```
cmd/server/main.go       → Entrypoint only: wiring, config, startup
internal/
  handler/               → HTTP layer: Gin handlers, request parsing, response serialization
  service/               → Business logic: protocol-agnostic, no Gin dependency
  server/                → OAuth2/OIDC core: token generation, grant dispatch, stores, PKCE
  model/                 → Data models and request/response structs
  middleware/             → Gin middleware: CORS, session, rate limiting
  router/                → Route definitions and middleware wiring
  oidc/                  → OIDC-specific: JWKS builder, discovery builder, key ID computation
```

**Layer dependency direction**: `handler` → `service` → `server` → `model`. Never reverse. `service` must NOT import `handler` or `gin`. `server` must NOT import `handler` or `service`.

### Import Grouping

Group imports in 3 sections, separated by blank lines:

```go
import (
    // 1. Standard library
    "context"
    "fmt"
    "time"

    // 2. Third-party packages
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"

    // 3. Internal packages
    "github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
    "github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/server"
)
```

### Naming Conventions

- **Exported functions/types**: PascalCase — `NewServer()`, `TokenGenerator`, `ValidateAccessToken()`
- **Unexported functions/types**: camelCase — `grantAuthorizationCode()`, `generateRandomString()`, `validateRedirectURI()`
- **Constructor pattern**: `NewXxx()` — `NewServer()`, `NewTokenGenerator()`, `NewAuthService()`
- **Method receivers**: Pointer receivers for structs with mutable state (`func (s *Server)`). Short, meaningful names — `s` for Server, `g` for TokenGenerator, `h` for Handler, `b` for builders.
- **Interfaces**: Not used extensively — concrete structs preferred. Define interfaces only when multiple implementations are expected (e.g., future DB-backed stores).
- **Constants**: No `const` blocks used; configuration via `AppConfig` struct or `TokenGenerator` fields (e.g., `AccessExpiry: 2 * time.Hour`).

### Error Handling

**Primary error type** (`internal/server/errors.go`): `OAuthError` struct with `Code` and `Description` fields, plus 8 constructor functions:

```go
// Server layer — use OAuthError constructors for protocol errors
return nil, ErrInvalidClient("authentication failed")
return nil, ErrInvalidGrant("authorization code not found or expired")
return nil, ErrInvalidScope(fmt.Sprintf("scope %q is not allowed for client %q", s, client.ID))
return nil, ErrUnsupportedGrantType(req.GrantType)
return nil, ErrUnauthorizedClient("password grant is not allowed for this client")
return nil, ErrInvalidRequest("missing required parameter")
return nil, ErrUnsupportedResponseType("only 'code' is supported per OAuth 2.1")
return nil, ErrServerError("internal error")

// For internal error wrapping (not OAuth protocol errors), use fmt.Errorf with %w
return nil, fmt.Errorf("server_error: failed to sign token: %w", err)
```

**Custom error types for structured errors**:

```go
// AuthorizeError (internal/server/authorize.go) — embeds *OAuthError, adds RedirectURI + State
type AuthorizeError struct {
    *OAuthError
    RedirectURI string
    State string
}

// TokenError (internal/service/token_service.go) — carries HTTP status code
type TokenError struct {
    Code string
    Description string
    HTTPStatus int
}
```

**Error propagation flow**: Server layer returns `*OAuthError` → Service layer uses `errors.As(err, &oauthErr)` to map to `*TokenError` with HTTP status → Handler layer reads `*TokenError` for HTTP response. The `service.ExtractOAuthError()` function remains as a fallback for non-structured errors (string-parsed error code prefix).

**OAuth 2.0 error codes used** (must match RFC 6749 §5.2 and extensions):

| Error Code | HTTP Status | When |
|---|---|---|
| `invalid_request` | 400 | Missing required parameter, malformed request |
| `invalid_client` | 401 | Client authentication failed (set `WWW-Authenticate` header) |
| `invalid_grant` | 400 | Authorization code / refresh token invalid, expired, or mismatch |
| `invalid_scope` | 400 | Requested scope not allowed for client |
| `unsupported_grant_type` | 400 | Unknown or disallowed grant_type |
| `unsupported_response_type` | 400 | response_type other than `code` |
| `unauthorized_client` | 400 | Client not allowed to use this grant type |
| `server_error` | 400 | Internal server error (random gen failure, signing failure, etc.) |
| `invalid_token` | 401 | Bearer token validation failed |
| `user_not_found` | 404 | UserInfo endpoint: user ID not in UserStore |
| `slow_down` | 429 | Rate limit exceeded |

**Handler layer error response pattern**:

```go
// Standard OAuth error response — use model.ErrorResponse
c.AbortWithStatusJSON(http.StatusBadRequest, model.ErrorResponse{
    Error: "invalid_grant", ErrorDescription: "authorization code not found or expired",
})

// For invalid_client errors — ALWAYS set WWW-Authenticate header
c.Header("WWW-Authenticate", `Basic realm="OAuth2"`)
c.AbortWithStatusJSON(http.StatusUnauthorized, model.ErrorResponse{
    Error: "invalid_client", ErrorDescription: "client authentication failed",
})

// Token endpoint — ALWAYS set Cache-Control headers
c.Header("Cache-Control", "no-store")
c.Header("Pragma", "no-cache")
```

### Handler Layer Conventions

- **Request binding**: `c.ShouldBindJSON(&req)` for JSON bodies, `c.PostForm("field")` for form-encoded, `c.Query("field")` for query params
- **Response format**: `c.JSON(status, data)` for JSON, `c.Redirect(http.StatusFound, url)` for redirects
- **Error flow**: Use `c.AbortWithStatusJSON()` (stops handler chain) or `c.AbortWithError()` (for internal errors). Never use `c.JSON()` alone for error responses in middleware chains.
- **Never panic in handlers** — return errors via the patterns above
- **Session access**: Always call `session.Start()` first, use type assertions with `ok` check for session values

### Service Layer Conventions

- **No Gin dependency** — services must NOT import `github.com/gin-gonic/gin`. HTTP context is bridged from handlers via plain Go types.
- **Input**: Receive typed structs (e.g., `*SessionData`, `*server.TokenRequest`)
- **Output**: Return typed structs + `error`. For OAuth protocol errors, return `*TokenError` or `*AuthorizeError` with proper HTTP status codes.
- **Stateless**: Services do not manage sessions or cookies. Handler passes session data in.

### Server Layer Conventions

- **Pure protocol logic**: OAuth2/OIDC spec implementation only. No HTTP awareness.
- **Error format**: Use `OAuthError` constructors from `errors.go` for protocol errors. For internal errors (e.g. crypto/rand failure, signing failure), use `fmt.Errorf` with `%w` wrapping and `server_error` prefix.
- **Return pattern**: `(*Result, error)` — nil result on error, non-nil on success
- **Stores**: In-memory via `sync.Map`. All store methods are goroutine-safe. Store constructors follow `NewXxxStore()` pattern.
- **Token generation**: All via `TokenGenerator` — RSA-2048 RS256 for JWTs, `crypto/rand` for opaque tokens. Never use `math/rand`. `GenerateRefreshToken()` and `GenerateAuthorizationCode()` return errors (propagated from `crypto/rand`).
- **Resource cleanup**: `AuthCodeStore` and `TokenStore` run background cleanup goroutines. Call `Close()` (via `Server.Close()`) to stop them.

### Security-Critical Coding Rules

- **Client secret comparison**: ALWAYS use `subtle.ConstantTimeCompare()` — never `==`
- **Random generation**: ALWAYS use `crypto/rand` — never `math/rand`
- **Secrets in logs**: NEVER log client secrets, tokens, authorization codes, or passwords
- **Password storage**: bcrypt via `golang.org/x/crypto/bcrypt` — `NewUserStore()` hashes passwords at creation; `AuthService.Authenticate()` uses `bcrypt.CompareHashAndPassword()`
- **Error messages**: Do not leak internal state in error descriptions (e.g., "invalid credentials" not "password mismatch for user admin")
- **PKCE verification**: S256 only. Never accept `plain` method. S256 comparison uses `subtle.ConstantTimeCompare` to prevent timing attacks.

### Swagger Annotations

Use swag DSL in godoc comments above handler functions. Format:

```go
// HandlerName godoc
// @Summary Short description
// @Description Longer description with details
// @Tags TagName
// @Accept json
// @Produce json
// @Param name location type required "Description"
// @Success 200 {object} model.ResponseType
// @Failure 400 {object} model.ErrorResponse
// @Router /path [method]
func (h *Handler) HandlerName(c *gin.Context) { ... }
```

After modifying any Swagger annotation, regenerate docs:

```bash
/Users/wei/go/bin/swag init -g cmd/server/main.go -o ./docs --parseDependency --parseInternal
```

### Model Struct Tags

- **JSON API models**: Always include `json` tags — use `omitempty` for optional fields
- **Swagger models**: Include `example` tags for Swagger UI display
- **Sensitive fields**: Use `json:"-"` to exclude (e.g., `User.Password`)

```go
type User struct {
    ID       string `json:"id"`
    Username string `json:"username"`
    Password string `json:"-"`                    // Never serialize
    Email    string `json:"email,omitempty"`      // Optional
    Name     string `json:"name,omitempty"`       // Optional
}
```

### Adding a New Endpoint

1. Define request/response structs in `internal/model/model.go`
2. Add business logic in the appropriate `service/` or `server/` file
3. Add handler method in the appropriate `internal/handler/` file with Swagger annotations
4. Register route in `internal/router/router.go`
5. Regenerate Swagger docs: `swag init -g cmd/server/main.go -o ./docs --parseDependency --parseInternal`
6. Verify: `go build ./...`, `go vet ./...`, `gofmt -l .`

### Adding a New Grant Type

1. Add grant type constant to `Client.AllowedGrantTypes` validation
2. Add handler in `internal/server/grant.go` — `func (s *Server) grantXxx(req *TokenRequest) (*TokenResponse, error)`
3. Add dispatch case in `Server.Token()` switch
4. Register clients with the new grant type in `cmd/server/main.go`
5. Update OIDC Discovery `GrantTypesSupported` in `internal/oidc/oidc.go`
6. Add Swagger annotations for new parameters

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
- Constant-time PKCE S256 verification (`subtle.ConstantTimeCompare`)
- Session/cookie handling — httpOnly, SameSite=Lax (dev), Secure+Strict (prod via `OAUTH_SECURE_COOKIE`)
- `auth_time` tracked from login through session → auth code → ID token
- `post_logout_redirect_uri` validation against registered client URIs in logout
- Rate limiting on token endpoint (10 req/min/IP, maxVisitors cap 10000, cleanup goroutine)
- Client secret storage — never log or expose
- Scope validation and enforcement (`openid` scope required for OIDC, required for UserInfo)
- Client grant type enforcement — each grant handler validates `IsGrantTypeAllowed()`
- Token revocation validates client ownership before deleting tokens
- Authorization code 1-minute expiry with single-use (deleted on exchange)
- Refresh token expiry check on retrieval (24h TTL)
- Password hashing via bcrypt (`golang.org/x/crypto/bcrypt`)
- .env file is gitignored — use it for secrets, never commit credentials
