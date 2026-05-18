# OAuth 2.0 + OpenID Connect Server

[![Go](https://img.shields.io/badge/Go-1.25.0-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A native Go implementation of an **OAuth 2.1** Authorization Server and **OpenID Connect 1.0** Provider. No external OAuth2 libraries — all protocol logic is implemented from scratch.

> OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. This project implements both protocols natively in Go, following OAuth 2.1 (RFC 9728) security recommendations.

## Features

- **OAuth 2.1 Compliant** — Only authorization code flow with PKCE. Implicit and hybrid flows are removed per security recommendations.
- **4 Grant Types** — `authorization_code`, `password`, `client_credentials`, `refresh_token`
- **OpenID Connect 1.0** — ID tokens as a first-class citizen, generated inline when `scope=openid`
- **JWT RS256** — Access tokens and ID tokens signed with RSA-2048 (RS256)
- **PKCE** — S256 code challenge method only (plain removed per OAuth 2.1)
- **Client Authentication** — `client_secret_basic` (Authorization header) and `client_secret_post` (body params) per RFC 6749 §2.3.1
- **JWKS & Discovery** — Standard OIDC endpoints for key distribution and provider metadata
- **Refresh Token Rotation** — Old tokens revoked on exchange, new pair issued
- **Rate Limiting** — Token endpoint protected (10 req/min/IP)
- **Swagger UI** — Interactive API documentation at `/swagger/`
- **Web Frontend** — React + TypeScript + Vite login/consent UI

## Architecture

```
cmd/server/main.go          Entrypoint: wires server, routes, session, Swagger, rate limiting, RSA key
internal/
  handler/handler.go        Gin HTTP handlers for all endpoints
  router/router.go          Route definitions and middleware wiring
  middleware/middleware.go   CORS, session, and rate-limit middleware
  service/
    auth_service.go         Login authentication and consent decision logic
    token_service.go        Token endpoint business logic and error mapping
    userinfo_service.go     OIDC UserInfo endpoint business logic
  server/
    server.go               Server struct, client registration, bearer token validation
    authorize.go            Authorization endpoint (code only per OAuth 2.1)
    grant.go                Token endpoint: dispatches by grant_type
    token.go                TokenGenerator: JWT RS256 access/id/refresh/code generation + validation
    store.go                In-memory stores (ClientStore, AuthCodeStore, TokenStore) via sync.Map
pkce.go VerifyPKCE(): S256-only code verifier validation (plain removed per OAuth 2.1)
  oidc/oidc.go              JWKSBuilder (RFC 7638 thumbprint kid), DiscoveryBuilder
  model/model.go            Data models: User, AppConfig, OIDCDiscovery, IDTokenClaims, request/response structs
web/                        React + TypeScript + Vite frontend (login/consent pages)
docs/                       Generated Swagger docs (swagger.json, swagger.yaml, docs.go)
```

### Core Design

- **No external OAuth2 library** — all OAuth 2.1 and OIDC logic is native in `internal/server/`
- **ID token is first-class** — generated inline in grant flows when `scope=openid`, not bolted on via interceptors
- **Authorization code carries full context** — `AuthorizationCode` struct stores `Nonce`, `ResponseType`, `CodeChallenge`, `CodeChallengeMethod`; no external state stores needed
- **Service layer separation** — business logic in `internal/service/`, HTTP concerns in `internal/handler/`

## Endpoints

| Route | Method | Handler | Description |
|---|---|---|---|
| `/api/login` | GET | `Login` | Check login status |
| `/api/login` | POST | `Login` | Authenticate user (JSON body) |
| `/api/auth` | GET | `Auth` | Get consent page context |
| `/api/auth` | POST | `Auth` | Submit consent decision (approve/deny) |
| `/oauth/authorize` | GET/POST | `Authorize` | OAuth2/OIDC authorization endpoint (code only) |
| `/oauth/token` | GET/POST | `Token` | OAuth2 token endpoint (rate-limited) |
| `/userinfo` | GET/POST | `UserInfo` | OIDC UserInfo endpoint |
| `/.well-known/openid-configuration` | GET | `Discovery` | OIDC Discovery document |
| `/.well-known/jwks.json` | GET | `JWKS` | JSON Web Key Set |
| `/api/test` | GET | middleware+test | Bearer token verification demo |
| `/logout` | GET | `Logout` | End session |
| `/swagger/*any` | GET | gin-swagger | Swagger UI |

## Grant Types

| grant_type | Method | ID Token? | Refresh Token? |
|---|---|---|---|
| `authorization_code` | `grantAuthorizationCode()` | Yes, if `scope` includes `openid` + userID | Yes |
| `password` | `grantPassword()` | Yes, if `scope` includes `openid` | Yes |
| `client_credentials` | `grantClientCredentials()` | Never (no user context) | Never (per RFC 6749) |
| `refresh_token` | `grantRefreshToken()` | Yes, if `scope` includes `openid` + userID | Yes (rotated) |

ID token inclusion is decided by `ShouldIncludeIDToken(scope, userID, userStore)` — returns true when `openid` scope is present AND userID is non-empty AND userStore is available.

## Token Details

| Token Type | Format | Signing | Expiry |
|---|---|---|---|
| Access Token | JWT RS256 (`iss`, `sub`, `aud`, `exp`, `iat`, `scope`) | RSA-2048 + `kid` header | 2 hours |
| ID Token | JWT RS256 (`iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, optional `nonce`/`email`/`name`) | RSA-2048 + `kid` header | 1 hour |
| Refresh Token | 32-byte random string (base64url) | — | 24 hours |
| Authorization Code | 24-byte random string (base64url) | — | 1 minute (single-use) |

- **kid**: RFC 7638 JWK thumbprint (SHA-256), base64url encoded
- **Refresh token rotation**: old refresh token + old access token deleted on exchange; new pair created

## Quick Start

### Prerequisites

- Go 1.25+
- Node.js 18+ (for frontend, optional)

### Run the Server

```bash
# Clone the repository
git clone https://github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect.git
cd OAuth-2.0-and-OpenID-Connect

# Start the server
go run cmd/server/main.go
```

The server starts at `http://localhost:9096`.

### Run with Custom RSA Key

```bash
# Generate an RSA key (optional; an ephemeral key is generated by default)
openssl genrsa -out private.pem 2048

# Start with the key
OAUTH_RSA_KEY_PATH=./private.pem go run cmd/server/main.go
```

### Run the Frontend

```bash
cd web
npm install
npm run dev
```

The frontend starts at `http://localhost:5173` (Vite dev server) and proxies API requests to the Go backend.

### Build the Frontend for Production

```bash
cd web
npm run build
```

The built assets are placed in `web/dist/` and served by the Go server automatically.

## Configuration

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `OAUTH_SECURE_COOKIE` | Set to `true` or `1` to enable Secure cookies with SameSite=Strict | `false` (Lax mode) |
| `OAUTH_RSA_KEY_PATH` | Path to PEM-encoded RSA private key file (PKCS1 or PKCS8) | (empty → ephemeral key generated at startup) |
| `OAUTH_SESSION_SECRET` | Session signing secret | `oauth2-session-secret` |

### Demo Configuration

| Setting | Value |
|---|---|
| Server | `http://localhost:9096` |
| Client 1 | ID: `000000`, Secret: `999999`, Redirect: `http://localhost:9094` |
| Client 2 | ID: `111111`, Secret: `11111111`, Redirect: `http://localhost:9094` |
| User 1 | Username: `admin`, Password: `admin` (ID=1) |
| User 2 | Username: `test`, Password: `test` (ID=2) |
| RSA Key | 2048-bit, generated at startup (or loaded from `OAUTH_RSA_KEY_PATH`) |
| kid | RFC 7638 JWK thumbprint (SHA-256) |

## Authorization Code Flow with PKCE

This is the primary and recommended flow per OAuth 2.1 (RFC 9728). All other grant types are optional; this is the only flow supported at the authorization endpoint. Implicit and hybrid flows are intentionally removed.

### Flow Diagram

```
┌──────────┐                              ┌──────────────┐                    ┌──────────┐
│  Client  │                              │  Auth Server  │                    │  Browser  │
│ (RP/App) │                              │ (Go Backend)  │                    │  (User)   │
└────┬─────┘                              └──────┬───────┘                    └─────┬────┘
     │                                           │                                  │
     │  ① Generate code_verifier + code_challenge │                                  │
│ (PKCE: S256 only) │ │
     │                                           │                                  │
     │  ② GET /oauth/authorize                   │                                  │
     │  ?response_type=code                      │                                  │
     │  &client_id=000000                        │                                  │
     │  &redirect_uri=http://localhost:9094       │                                  │
     │  &scope=openid+profile+email              │                                  │
     │  &state=xyz123                            │                                  │
     │  &nonce=n-0S6_WzA2Mj                      │                                  │
     │  &code_challenge=BASE64URL_SHA256(verifier)│                                 │
     │  &code_challenge_method=S256               │                                 │
     │ ─────────────────────────────────────────>│                                  │
     │                                           │                                  │
     │                                           │  ③ No session? → 302 /login      │
     │                                           │ ─────────────────────────────────>│
     │                                           │                                  │
     │                                           │  ④ POST /api/login               │
     │                                           │  {username, password}            │
     │                                           │ <─────────────────────────────────│
     │                                           │                                  │
     │                                           │  ⑤ 200 {redirect: "/auth"}       │
     │                                           │ ─────────────────────────────────>│
     │                                           │                                  │
     │                                           │  ⑥ GET /api/auth                 │
     │                                           │  ?client_id=&scope=              │
     │                                           │ <─────────────────────────────────│
     │                                           │                                  │
     │                                           │  ⑦ 200 {user_id, client_id, scope}│
     │                                           │ ─────────────────────────────────>│
     │                                           │                                  │
     │                                           │  ⑧ POST /api/auth                │
     │                                           │  {authorize: true}               │
     │                                           │ <─────────────────────────────────│
     │                                           │                                  │
     │                                           │  ⑨ 200 {redirect: original /oauth/authorize URL}│
     │                                           │ ─────────────────────────────────>│
     │                                           │                                  │
     │                                           │  ⑩ Browser re-visits /oauth/authorize (with session)│
     │                                           │ <─────────────────────────────────│
     │                                           │                                  │
     │                                           │  ⑪ Validate client, scope, PKCE  │
     │                                           │  Generate authorization code      │
     │                                           │  Store: code + PKCE challenge + nonce│
     │                                           │                                  │
     │  ⑫ 302 redirect_uri?code=AUTH_CODE&state=xyz123                               │
     │ <─────────────────────────────────────────│                                  │
     │                                           │                                  │
     │  ⑬ POST /oauth/token                       │                                  │
     │  grant_type=authorization_code             │                                  │
     │  code=AUTH_CODE                            │                                  │
     │  redirect_uri=http://localhost:9094         │                                  │
     │  client_id=000000                          │                                  │
     │  client_secret=999999                      │                                  │
     │  code_verifier=ORIGINAL_VERIFIER            │                                  │
     │ ─────────────────────────────────────────>│                                  │
     │                                           │                                  │
     │                                           │  ⑭ Verify PKCE:                  │
│ │ S256: SHA256(verifier) == stored challenge│
│ │ Delete auth code (single-use) │
     │                                           │  Generate access_token + id_token + refresh_token│
     │                                           │                                  │
     │  ⑮ 200 {access_token, id_token, refresh_token, ...}                          │
     │ <─────────────────────────────────────────│                                  │
     │                                           │                                  │
     │  ⑯ GET /userinfo                           │                                  │
     │  Authorization: Bearer <access_token>      │                                  │
     │ ─────────────────────────────────────────>│                                  │
     │                                           │                                  │
     │  ⑰ 200 {sub, name, email, email_verified} │                                  │
     │ <─────────────────────────────────────────│                                  │
```

### Step-by-Step Explanation

#### ① PKCE Preparation (Client-side)

Before initiating the flow, the client generates a `code_verifier` and derives a `code_challenge`:

- **code_verifier**: A cryptographically random string, 43–128 characters long, containing only `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"` (unreserved URL-safe characters per RFC 7636 §4.1)
- **code_challenge**: Derived from the verifier using the S256 method:
  - **S256** (required): `BASE64URL(SHA256(code_verifier))`

The `code_verifier` is kept secret on the client; only the `code_challenge` is sent in the authorization request. This binds the authorization code to the original client, preventing authorization code interception attacks.

> **Implementation**: The server validates PKCE in `internal/server/pkce.go` via `VerifyPKCE(challenge, method, verifier)`. The server only supports `S256` method per OAuth 2.1 (RFC 9728 §7.1). The `plain` method is removed. If `challenge` is empty, PKCE verification passes (for backward compatibility with non-PKCE clients, but `code_challenge` is required at the authorization endpoint).

#### ② Authorization Request

The client redirects the user agent (browser) to the authorization endpoint:

| Parameter | Required | Description |
|---|---|---|
| `response_type` | Yes | Must be `code` (only value per OAuth 2.1) |
| `client_id` | Yes | Client identifier registered with the server |
| `redirect_uri` | Yes | Must exactly match a registered redirect URI |
| `scope` | No | Space-delimited scopes (e.g. `openid profile email`). Defaults to client's allowed scopes if omitted. |
| `state` | Recommended | Opaque value returned verbatim in the redirect; prevents CSRF |
| `nonce` | Recommended | String value for ID token replay protection (used when `scope` includes `openid`) |
| `code_challenge` | Required | PKCE code challenge derived from `code_verifier` (required per OAuth 2.1) |
| `code_challenge_method` | Required | Must be `S256` (only supported method per OAuth 2.1 RFC 9728 §7.1) |

> **Server processing** (`internal/server/authorize.go` — `Server.Authorize()`):
> 1. Validates `client_id` exists in `ClientStore`
> 2. Validates `redirect_uri` matches a registered URI (exact match)
> 3. Validates requested `scope` against client's allowed scopes
> 4. Requires `code_challenge` parameter (PKCE mandatory per OAuth 2.1)
> 5. Requires `code_challenge_method=S256` (only supported method)
> 6. Enforces `response_type=code` only (rejects `token`, `id_token`, etc. with `unsupported_response_type`)
> 7. If all checks pass, calls `authorizeCode()` which generates a random 24-byte code and stores it

#### ③ Login Gate (Session Check)

When the authorization endpoint receives the request, it checks for an authenticated session:

> **Server processing** (`internal/handler/handler.go` — `Handler.Authorize()`):
> - Reads `LoggedInUserID` from the server-side session
> - If not logged in: stores the full request URI as `ReturnURI` in the session, then redirects to `/login` with `302 Found`

#### ④ User Authentication (Login)

The user submits credentials via the login API:

```
POST /api/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin"
}
```

**Response** (200 OK):

```json
{
  "redirect": "/oauth/authorize?response_type=code&client_id=000000&..."
}
```

The `redirect` points to the original authorization URL that was saved in the session at step ③.

> **Server processing** (`internal/service/auth_service.go` — `AuthService.Authenticate()`):
> - Looks up user by `username` in `UserStore`
> - Compares password (plain text in demo; use bcrypt in production)
> - On success: sets `LoggedInUserID` and `LoggedInUsername` in the session

**Error response** (401 Unauthorized):

```json
{
  "error": "invalid_credentials",
  "error_description": "Invalid username or password"
}
```

#### ⑤⑥⑦ Consent (Authorization Decision)

After login, the client retrieves consent context and submits the user's decision:

**Get consent context:**

```
GET /api/auth?client_id=000000&scope=openid%20profile%20email
```

**Response** (200 OK):

```json
{
  "user_id": "1",
  "client_id": "000000",
  "scope": "openid profile email"
}
```

**Submit consent:**

```
POST /api/auth
Content-Type: application/json

{
  "authorize": true
}
```

**Response** (200 OK):

```json
{
  "redirect": "/oauth/authorize?response_type=code&client_id=000000&..."
}
```

> **Server processing** (`internal/service/auth_service.go` — `AuthService.ProcessAuthDecision()`):
> - If `deny: true`: redirects to `ReturnURI` with `error=access_denied` appended to query
> - If `authorize: true`: returns the stored `ReturnURI` (the original `/oauth/authorize` URL)

#### ⑧⑨⑩ Re-visit Authorization Endpoint

The browser follows the redirect back to `/oauth/authorize`. This time the user has an authenticated session, so the login gate passes.

#### ⑪ Authorization Code Generation

The server validates the request (client, redirect URI, scope, response type) and generates an authorization code:

> **Server processing** (`internal/server/authorize.go` — `Server.authorizeCode()`):
> - Generates a random 24-byte string (base64url-encoded) as the authorization code
> - Stores an `AuthorizationCode` struct containing:
>   - `Code`, `ClientID`, `UserID`, `RedirectURI`, `Scope`
>   - `Nonce` — preserved for ID token generation
>   - `CodeChallenge`, `CodeChallengeMethod` — preserved for PKCE verification at token exchange
> - `ExpiresAt` — 1 minute from now
> - The authorization code carries **all context** needed for token exchange — no external state stores required

#### ⑫ Authorization Response (Redirect)

The server redirects the user agent back to the client's `redirect_uri` with the authorization code:

```
HTTP/1.1 302 Found
Location: http://localhost:9094?code=RECEIVED_AUTH_CODE&state=xyz123
```

| Parameter | Description |
|---|---|
| `code` | The authorization code (24-byte base64url string, expires in 1 minute, single-use) |
| `state` | The exact `state` value from the authorization request (if provided) |

#### ⑬ Token Exchange

The client exchanges the authorization code for tokens at the token endpoint. Client credentials can be provided via the Authorization header (`client_secret_basic`) or the request body (`client_secret_post`), per RFC 6749 §2.3.1. The Authorization header takes precedence if both are present.

**Using Authorization header (client_secret_basic):**

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code
&code=RECEIVED_AUTH_CODE
&redirect_uri=http://localhost:9094
&code_verifier=ORIGINAL_CODE_VERIFIER
```

**Using request body (client_secret_post):**

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=RECEIVED_AUTH_CODE
&redirect_uri=http://localhost:9094
&client_id=000000
&client_secret=999999
&code_verifier=ORIGINAL_CODE_VERIFIER
```

| Parameter | Required | Description |
|---|---|---|
| `grant_type` | Yes | Must be `authorization_code` |
| `code` | Yes | The authorization code received in step ⑫ |
| `redirect_uri` | Yes | Must match the `redirect_uri` from step ② |
| `client_id` | Conditional | Client identifier (required if not using Authorization header) |
| `client_secret` | Conditional | Client secret (required if not using Authorization header) |
| `code_verifier` | Conditional | The original PKCE verifier from step ①. Required if `code_challenge` was sent in step ②. |
| `Authorization` | Conditional | `Basic base64(client_id:client_secret)` — takes precedence over body params |

#### ⑭ PKCE Verification & Token Generation

> **Server processing** (`internal/server/grant.go` — `Server.grantAuthorizationCode()`):
> 1. **Client authentication**: validates `client_id` + `client_secret`
> 2. **Code lookup**: retrieves `AuthorizationCode` from `AuthCodeStore`
> 3. **Code deletion**: immediately deletes the code (single-use — prevents replay)
> 4. **Client binding check**: verifies code was issued to the same `client_id`
> 5. **Redirect URI check**: verifies `redirect_uri` matches the one stored in the code
> 6. **PKCE verification** (`internal/server/pkce.go` — `VerifyPKCE()`):
> - `S256`: `BASE64URL(SHA256(code_verifier)) == stored_code_challenge`
> - If `code_challenge` was empty (PKCE not used), verification passes
> 7. **Scope validation**: re-validates that the code's scope is still permitted for the client
> 8. **Token generation**:
>    - **Access token**: JWT RS256 with `iss`, `sub`, `aud`, `exp`, `iat`, `scope` claims (2h expiry)
>    - **Refresh token**: 32-byte random string (24h expiry)
>    - **ID token**: JWT RS256 with `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `email`, `name` (1h expiry) — only if `scope` includes `openid` AND `userID` is non-empty

#### ⑮ Token Response

**Success** (200 OK):

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9...",
  "token_type": "Bearer",
  "expires_in": 7200,
  "refresh_token": "ODk4YWY2NjktMmQ0OC00MWJhLWJj...",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9..."
}
```

| Field | Description |
|---|---|
| `access_token` | JWT RS256 signed with the server's RSA private key |
| `token_type` | Always `Bearer` |
| `expires_in` | Access token lifetime in seconds (7200 = 2 hours) |
| `refresh_token` | Opaque string for obtaining new token pairs (rotated on use) |
| `scope` | The granted scope (may differ from requested if narrowed) |
| `id_token` | OIDC ID token (present only when `scope` includes `openid`) |

**Error responses:**

| HTTP Status | Error Code | Description |
|---|---|---|
| 401 | `invalid_client` | Client authentication failed |
| 400 | `invalid_grant` | Code not found, expired, already used, PKCE failed, or client/redirect mismatch |
| 400 | `invalid_scope` | Code's scope no longer permitted for the client |

#### ⑯⑰ UserInfo (Optional)

After obtaining tokens, the client can call the UserInfo endpoint to retrieve profile claims:

```
GET /userinfo
Authorization: Bearer <access_token>
```

**Response** (200 OK):

```json
{
  "sub": "1",
  "name": "Admin User",
  "email": "admin@example.com",
  "email_verified": true
}
```

### Complete cURL Demo

```bash
#!/bin/bash
set -e

SERVER="http://localhost:9096"
CLIENT_ID="000000"
CLIENT_SECRET="999999"
REDIRECT_URI="http://localhost:9094"

# ─── Step ①: Generate PKCE verifier and challenge ───
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '/+=' | head -c 43)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

echo "code_verifier:  $CODE_VERIFIER"
echo "code_challenge: $CODE_CHALLENGE"

# ─── Step ②: Build authorization URL ───
AUTH_URL="${SERVER}/oauth/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=openid%20profile%20email&state=xyz123&nonce=n-0S6_WzA2Mj&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

echo ""
echo "Open this URL in a browser to start the flow:"
echo "$AUTH_URL"

# ─── Step ④: Login via API (simulate user login) ───
echo ""
echo "Logging in..."
LOGIN_RESP=$(curl -s -c /tmp/oauth_cookies -b /tmp/oauth_cookies -X POST "${SERVER}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}')
echo "Login response: $LOGIN_RESP"

# ─── Step ⑤⑥⑦: Submit consent (authorize the request) ───
echo ""
echo "Submitting consent..."
AUTH_RESP=$(curl -s -c /tmp/oauth_cookies -b /tmp/oauth_cookies -X POST "${SERVER}/api/auth" \
  -H "Content-Type: application/json" \
  -d '{"authorize":true}')
echo "Consent response: $AUTH_RESP"

# ─── Step ⑩⑪⑫: Visit the authorize endpoint with session ───
echo ""
echo "Visiting authorization endpoint..."
AUTH_REDIRECT=$(curl -s -c /tmp/oauth_cookies -b /tmp/oauth_cookies -o /dev/null -w '%{redirect_url}' "$AUTH_URL")
echo "Redirect URL: $AUTH_REDIRECT"

# Extract the authorization code from the redirect URL
AUTH_CODE=$(echo "$AUTH_REDIRECT" | sed 's/.*code=\([^&]*\).*/\1/')
echo "Authorization code: $AUTH_CODE"

# ─── Step ⑬⑭⑮: Exchange code for tokens ───
echo ""
echo "Exchanging authorization code for tokens..."
# Option A: Using Authorization header (client_secret_basic, recommended)
TOKEN_RESP=$(curl -s -X POST "${SERVER}/oauth/token" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=authorization_code" \
  -d "code=${AUTH_CODE}" \
  -d "redirect_uri=${REDIRECT_URI}" \
  -d "code_verifier=${CODE_VERIFIER}")

# Option B: Using request body (client_secret_post)
# TOKEN_RESP=$(curl -s -X POST "${SERVER}/oauth/token" \
#   -d "grant_type=authorization_code" \
#   -d "code=${AUTH_CODE}" \
#   -d "redirect_uri=${REDIRECT_URI}" \
#   -d "client_id=${CLIENT_ID}" \
#   -d "client_secret=${CLIENT_SECRET}" \
#   -d "code_verifier=${CODE_VERIFIER}")
echo "Token response:"
echo "$TOKEN_RESP" | python3 -m json.tool 2>/dev/null || echo "$TOKEN_RESP"

# ─── Step ⑯⑰: Call UserInfo with the access token ───
ACCESS_TOKEN=$(echo "$TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
if [ -n "$ACCESS_TOKEN" ]; then
  echo ""
  echo "Calling UserInfo endpoint..."
  USERINFO_RESP=$(curl -s "${SERVER}/userinfo" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")
  echo "UserInfo response:"
  echo "$USERINFO_RESP" | python3 -m json.tool 2>/dev/null || echo "$USERINFO_RESP"
fi

# Cleanup
rm -f /tmp/oauth_cookies
```

### PKCE Verification Detail

The PKCE verification is implemented in `internal/server/pkce.go`:

```
VerifyPKCE(challenge, method, verifier) → bool

┌──────────────────────┐
│ challenge == "" ? │──Yes──→ return true (no PKCE challenge stored)
└──────────┬───────────┘
          │ No
          ▼
┌──────────────────────┐
│ method == "S256" ? │──Yes──→ SHA256(verifier) → BASE64URL → compare with challenge
└──────────┬───────────┘
          │ No
          ▼
   return false (unsupported method, plain removed per OAuth 2.1)
```

**Key security properties:**
- The `code_verifier` is never sent in the authorization request — only the `code_challenge` is sent
- An attacker who intercepts the authorization code cannot exchange it without the `code_verifier`
- With `S256`, the original `code_verifier` cannot be derived from the `code_challenge` (one-way hash)
- The `plain` method is removed per OAuth 2.1 (RFC 9728 §7.1) — only `S256` is supported
- The `code_challenge` and `code_challenge_method` are stored in the `AuthorizationCode` struct and verified at token exchange time

## Other Grant Types

All grant types support both `client_secret_basic` (Authorization header) and `client_secret_post` (body params) for client authentication. The `-u client_id:client_secret` flag in curl sets the `Authorization: Basic` header automatically.

### Password Grant

```bash
# Using Authorization header (client_secret_basic)
curl -X POST http://localhost:9096/oauth/token \
  -u 000000:999999 \
  -d "grant_type=password" \
  -d "username=admin" \
  -d "password=admin" \
  -d "scope=openid profile email"
```

### Client Credentials Grant

```bash
# Using Authorization header (client_secret_basic)
curl -X POST http://localhost:9096/oauth/token \
  -u 000000:999999 \
  -d "grant_type=client_credentials" \
  -d "scope=profile email"
```

### Refresh Token

```bash
# Using Authorization header (client_secret_basic)
curl -X POST http://localhost:9096/oauth/token \
  -u 000000:999999 \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN"
```

### UserInfo

```bash
curl http://localhost:9096/userinfo \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### OIDC Discovery

```bash
curl http://localhost:9096/.well-known/openid-configuration
```

### JWKS

```bash
curl http://localhost:9096/.well-known/jwks.json
```

## Swagger Documentation

Interactive API documentation is available at:

```
http://localhost:9096/swagger/index.html
```

To regenerate Swagger docs after modifying annotations:

```bash
swag init -g cmd/server/main.go -o ./docs --parseDependency --parseInternal
```

## Tech Stack

**Backend:**
- [Gin](https://github.com/gin-gonic/gin) — HTTP framework
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) — JWT RS256 signing and validation
- [go-jose/go-jose](https://github.com/go-jose/go-jose) — JWK thumbprint (RFC 7638 kid)
- [go-session/session](https://github.com/go-session/session) — Server-side session management
- [swaggo/swag](https://github.com/swaggo/swag) + [gin-swagger](https://github.com/swaggo/gin-swagger) — Swagger docs

**Frontend:**
- [React](https://react.dev/) 19 + TypeScript
- [Vite](https://vite.dev/) 8
- [React Router](https://reactrouter.com/) 7

## Security Considerations

- **RSA-2048 RS256** signing with `kid` via RFC 7638 JWK thumbprint
- **PKCE** — S256 only (plain removed per OAuth 2.1 RFC 9728 §7.1); `code_challenge` required at authorization endpoint
- **Authorization code single-use** — deleted immediately on exchange
- **Redirect URI strict matching** — exact match against registered URIs
- **Refresh token rotation** — old token pair revoked on each exchange
- **Scope validation** — requested scopes checked against client's allowed scopes; `openid` not allowed for `client_credentials`
- **Rate limiting** — token endpoint: 10 requests/minute per IP
- **Session cookies** — httpOnly, SameSite=Lax (dev) / Secure+Strict (prod via `OAUTH_SECURE_COOKIE`)
- **Login gate** — authorize endpoint redirects to `/login` if not authenticated
- **Client authentication** — `client_secret_basic` (Authorization header) and `client_secret_post` (body params) supported per RFC 6749 §2.3.1; conflicting credentials rejected with `invalid_client`
- **Client secrets** — never logged or exposed in responses

## Known Limitations

- **In-memory stores only** — all state lost on restart. Add DB-backed stores (Redis, PostgreSQL) for production.
- **No dynamic client registration** — clients are registered in code. Add a registration endpoint for production.
- **No token introspection endpoint** — add [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662).
- **No encrypted tokens** — consider `go-jose` for JWE if needed.
- **No tests** — add unit + integration tests.

## License

[MIT](LICENSE)
