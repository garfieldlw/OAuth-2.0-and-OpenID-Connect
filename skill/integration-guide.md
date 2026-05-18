# 第三方接入指南 — Authorization Code Flow with PKCE

本文档说明如何让第三方应用（Relying Party）接入本身份验证系统。本系统仅支持 **Authorization Code Flow with PKCE (S256)**，这是 OAuth 2.1 (RFC 9728) 唯一允许的授权端点流程。

> Implicit Flow 和 Hybrid Flow 已按 OAuth 2.1 安全建议移除。所有 Token（access_token、id_token、refresh_token）仅通过 Token Endpoint 的响应体下发，不会暴露在浏览器 URL 中。

---

## 目录

- [前置条件](#前置条件)
- [端点列表](#端点列表)
- [Scope 与数据权限](#scope-与数据权限)
- [完整流程图](#完整流程图)
- [分步详解](#分步详解)
  - [第 1 步：生成 PKCE Code Verifier 和 Code Challenge](#第-1-步生成-pkce-code-verifier-和-code-challenge)
  - [第 2 步：构造 Authorization URL 并重定向用户](#第-2-步构造-authorization-url-并重定向用户)
  - [第 3 步：用户登录并授权](#第-3-步用户登录并授权)
  - [第 4 步：接收 Authorization Code](#第-4-步接收-authorization-code)
  - [第 5 步：用 Code 换取 Token](#第-5-步用-code-换取-token)
  - [第 6 步：调用 UserInfo 获取用户信息](#第-6-步调用-userinfo-获取用户信息)
  - [第 7 步：验证 ID Token](#第-7-步验证-id-token)
  - [第 8 步：使用 Refresh Token 刷新](#第-8-步使用-refresh-token-刷新)
  - [第 9 步：撤销 Token](#第-9-步撤销-token)
  - [第 10 步：登出](#第-10-步登出)
- [错误处理](#错误处理)
- [安全注意事项](#安全注意事项)
- [完整 cURL 示例](#完整-curl-示例)

---

## 前置条件

在接入之前，你需要从本系统管理员处获取以下信息：

| 参数 | 说明 | 示例 |
|------|------|------|
| `client_id` | 分配给第三方应用的客户端标识 | `000000` |
| `client_secret` | 客户端密钥（用于 Token Endpoint 认证） | `999999` |
| `redirect_uri` | 已注册的回调地址（必须精确匹配） | `http://localhost:9094/callback` |

> 也可通过 OIDC Discovery 自动获取端点地址：`GET /.well-known/openid-configuration`

---

## 端点列表

| 端点 | URL | 方法 | 说明 |
|------|-----|------|------|
| Authorization | `/oauth/authorize` | GET / POST | 授权端点，颁发 Authorization Code |
| Token | `/oauth/token` | POST | Token 端点，换取 Token（仅 POST） |
| UserInfo | `/userinfo` | GET / POST | OIDC UserInfo 端点，获取用户 Claims |
| Revocation | `/oauth/revoke` | POST | Token 撤销端点 (RFC 7009) |
| Discovery | `/.well-known/openid-configuration` | GET | OIDC Provider 配置发现 |
| JWKS | `/.well-known/jwks.json` | GET | JSON Web Key Set（验证 JWT 签名） |
| End Session | `/logout` | GET | 登出端点 |

> 基础 URL（Issuer）：`http://localhost:9096`（开发环境）

---

## Scope 与数据权限

本系统支持以下 Scope，**返回的数据字段严格按授权的 Scope 过滤**（OIDC Core 1.0 §5.4）：

| Scope | 返回的 Claims | 说明 |
|-------|---------------|------|
| `openid` | `sub` | 必须。最小的 OIDC 身份标识 |
| `profile` | `name` | 用户基本信息 |
| `email` | `email`, `email_verified` | 用户邮箱信息 |

### 不同 Scope 组合的响应示例

**scope=openid**（仅身份标识）：
```json
{
  "sub": "1"
}
```

**scope=openid profile**（身份 + 基本信息）：
```json
{
  "sub": "1",
  "name": "Admin User"
}
```

**scope=openid email**（身份 + 邮箱）：
```json
{
  "sub": "1",
  "email": "admin@example.com",
  "email_verified": true
}
```

**scope=openid profile email**（全部）：
```json
{
  "sub": "1",
  "name": "Admin User",
  "email": "admin@example.com",
  "email_verified": true
}
```

> ID Token 中的 Claims 同样遵循此 Scope 过滤规则。

---

## 完整流程图

```
┌───────────┐    ┌───────────────────┐    ┌──────────────┐
│  第三方应用  │    │  身份验证服务器 (OP)  │    │  用户浏览器    │
│  (RP/Client)│    │  (Go Backend)      │    │  (End User)  │
└─────┬─────┘    └─────────┬─────────┘    └──────┬───────┘
      │                    │                      │
      │ ① 生成 PKCE        │                      │
      │  code_verifier     │                      │
      │  code_challenge    │                      │
      │  = S256(verifier)  │                      │
      │                    │                      │
      │ ② 构造 Authorization URL                     │
      │────────────────────│─────────────────────>│
      │                    │                      │
      │  302 重定向到 /login（无 session）             │
      │<───────────────────│──────────────────────│
      │                    │                      │
      │ ③ 用户在浏览器中登录并授权                      │
      │                    │<─────────────────────│
      │                    │  POST /api/login     │
      │                    │  POST /api/auth      │
      │                    │─────────────────────>│
      │                    │                      │
      │                    │  ④ 重定向回 redirect_uri │
      │                    │  ?code=XXX&state=YYY │
      │<───────────────────│──────────────────────│
      │                    │                      │
      │ ⑤ POST /oauth/token 用 code 换 token        │
      │───────────────────>│                      │
      │                    │                      │
      │  ⑤ 返回 access_token + id_token + refresh_token
      │<───────────────────│                      │
      │                    │                      │
      │ ⑥ GET /userinfo    │                      │
      │  Authorization:    │                      │
      │  Bearer <token>    │                      │
      │───────────────────>│                      │
      │                    │                      │
      │  返回用户 Claims (按 scope 过滤)              │
      │<───────────────────│                      │
      │                    │                      │
      │ ⑦ 验证 ID Token 签名和 Claims               │
      │ (本地验证，不请求服务器)                       │
      │                    │                      │
```

---

## 分步详解

### 第 1 步：生成 PKCE Code Verifier 和 Code Challenge

PKCE (Proof Key for Code Exchange) 是 OAuth 2.1 **强制要求**的安全机制，防止 Authorization Code 被拦截攻击。本系统仅支持 **S256** 方法。

#### 规则

- **code_verifier**：43-128 个字符，仅包含 `[A-Z] [a-z] [0-9] - . _ ~`
- **code_challenge**：`BASE64URL(SHA256(code_verifier))`
- **code_challenge_method**：必须为 `S256`

#### 生成示例

**Python**：

```python
import secrets
import base64
import hashlib

# 生成 code_verifier（43-128 字符，URL 安全）
code_verifier = secrets.token_urlsafe(32)  # 43 字符

# 计算 code_challenge = BASE64URL(SHA256(code_verifier))
digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

print(f"code_verifier:  {code_verifier}")
print(f"code_challenge: {code_challenge}")
```

**Node.js**：

```javascript
const crypto = require('crypto');

// 生成 code_verifier
const codeVerifier = crypto.randomBytes(32).toString('base64url');

// 计算 code_challenge
const codeChallenge = crypto
  .createHash('sha256')
  .update(codeVerifier)
  .digest('base64url');

console.log('code_verifier: ', codeVerifier);
console.log('code_challenge:', codeChallenge);
```

**Go**：

```go
package main

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
)

func main() {
    // 生成 code_verifier
    b := make([]byte, 32)
    rand.Read(b)
    codeVerifier := base64.RawURLEncoding.EncodeToString(b)

    // 计算 code_challenge
    h := sha256.Sum256([]byte(codeVerifier))
    codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

    fmt.Printf("code_verifier:  %s\n", codeVerifier)
    fmt.Printf("code_challenge: %s\n", codeChallenge)
}
```

> **安全提示**：`code_verifier` 必须在客户端本地保存，**绝不能**发送到 Authorization URL 中。只有 `code_challenge` 出现在授权请求里。

---

### 第 2 步：构造 Authorization URL 并重定向用户

将用户浏览器重定向到 Authorization Endpoint：

```
GET /oauth/authorize?response_type=code
                    &client_id=000000
                    &redirect_uri=http://localhost:9094/callback
                    &scope=openid+profile+email
                    &state=xyz123
                    &nonce=n-0S6_WzA2Mj
                    &code_challenge=BASE64URL_SHA256_VERIFIER
                    &code_challenge_method=S256
```

#### 参数说明

| 参数 | 必须 | 说明 |
|------|------|------|
| `response_type` | **是** | 必须为 `code`（唯一值） |
| `client_id` | **是** | 分配的客户端标识 |
| `redirect_uri` | **是** | 必须精确匹配已注册的回调 URI |
| `scope` | 否 | 空格分隔的权限范围，如 `openid profile email`。省略则使用客户端默认 scope |
| `state` | **强烈建议** | 不透明字符串，原样返回，防止 CSRF 攻击 |
| `nonce` | 建议 | ID Token 重放保护（scope 包含 openid 时建议提供） |
| `code_challenge` | **是** | PKCE Code Challenge（S256 计算） |
| `code_challenge_method` | **是** | 必须为 `S256` |

#### 请求示例

```bash
# 完整 Authorization URL
AUTH_URL="http://localhost:9096/oauth/authorize?\
response_type=code\
&client_id=000000\
&redirect_uri=http%3A%2F%2Flocalhost%3A9094%2Fcallback\
&scope=openid%20profile%20email\
&state=xyz123\
&nonce=n-0S6_WzA2Mj\
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM\
&code_challenge_method=S256"

# 在浏览器中打开此 URL
echo "请在浏览器中打开: $AUTH_URL"
```

#### 参数校验规则

- `response_type` 不是 `code` → 返回 `unsupported_response_type`
- `client_id` 不存在 → 返回 `invalid_client`
- `redirect_uri` 不匹配 → 返回 `invalid_request`
- `scope` 超出客户端允许范围 → 返回 `invalid_scope`
- `code_challenge` 缺失 → 返回 `invalid_request`（PKCE 是必须的）
- `code_challenge_method` 不是 `S256` → 返回 `invalid_request`

---

### 第 3 步：用户登录并授权

用户到达 Authorization Endpoint 后，如果尚未登录，系统会自动重定向到登录页面。用户需要：

1. **登录**：输入用户名和密码
2. **授权**：查看请求的权限范围，选择同意或拒绝

> 此步骤在浏览器中完成，第三方应用无需处理。服务器通过 session 维持用户状态。

---

### 第 4 步：接收 Authorization Code

用户授权后，服务器将浏览器重定向回 `redirect_uri`，并携带参数：

```
HTTP/1.1 302 Found
Location: http://localhost:9094/callback?code=AUTH_CODE_HERE&state=xyz123
```

| 参数 | 说明 |
|------|------|
| `code` | Authorization Code（24 字节随机字符串，base64url 编码，1 分钟有效，单次使用） |
| `state` | 第 2 步中传入的 `state` 原值 |

#### 第三方应用处理

```python
# 在回调处理中
auth_code = request.args.get('code')
returned_state = request.args.get('state')

# 验证 state 防止 CSRF
if returned_state != expected_state:
    raise SecurityError("state 不匹配，可能遭受 CSRF 攻击")
```

> **重要**：Authorization Code 有效期仅 1 分钟，且只能使用一次。交换后立即失效。

---

### 第 5 步：用 Code 换取 Token

第三方应用在**后端**向 Token Endpoint 发送 POST 请求，用 Authorization Code 换取 Token。此请求**必须**在 Code 过期前完成。

#### 请求

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
```

客户端认证方式（二选一，推荐方式一）：

**方式一：Authorization Header（client_secret_basic，推荐）**：

```bash
curl -X POST http://localhost:9096/oauth/token \
  -u "000000:999999" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "redirect_uri=http://localhost:9094/callback" \
  -d "code_verifier=ORIGINAL_CODE_VERIFIER"
```

等价于：

```bash
curl -X POST http://localhost:9096/oauth/token \
  -H "Authorization: Basic BASE64(000000:999999)" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "redirect_uri=http://localhost:9094/callback" \
  -d "code_verifier=ORIGINAL_CODE_VERIFIER"
```

**方式二：Request Body（client_secret_post）**：

```bash
curl -X POST http://localhost:9096/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "redirect_uri=http://localhost:9094/callback" \
  -d "client_id=000000" \
  -d "client_secret=999999" \
  -d "code_verifier=ORIGINAL_CODE_VERIFIER"
```

#### 参数说明

| 参数 | 必须 | 说明 |
|------|------|------|
| `grant_type` | **是** | 必须为 `authorization_code` |
| `code` | **是** | 第 4 步收到的 Authorization Code |
| `redirect_uri` | **是** | 必须与第 2 步中的 `redirect_uri` 完全一致 |
| `client_id` | 条件 | 未使用 Authorization Header 时必须提供 |
| `client_secret` | 条件 | 未使用 Authorization Header 时必须提供 |
| `code_verifier` | **是** | 第 1 步生成的原始 Code Verifier |

> `Authorization` Header 和 Body 中的 `client_id` 不能同时存在且不一致，否则返回 `invalid_client`。

#### 成功响应

```json
HTTP/1.1 200 OK
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwOTYiLCJzdWIiOiIxIiwiYXVkIjoiMDAwMDAwIiwiZXhwIjoxNzAwMDAwMDAwLCJpYXQiOjE3MDAwMDAwMDAsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwifQ.SIGNATURE",
  "token_type": "Bearer",
  "expires_in": 7200,
  "refresh_token": "ODk4YWY2NjktMmQ0OC00MWJhLWJjZDUtYTBmMWI0N2ViYzRl",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii4uLiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwOTYiLCJzdWIiOiIxIiwiYXVkIjoiMDAwMDAwIiwiZXhwIjoxNzAwMDAwMDAwLCJpYXQiOjE3MDAwMDAwMDAsImF1dGhfdGltZSI6MTcwMDAwMDAwMCwibm9uY2UiOiJuLTBTNl9XekEyTWoiLCJuYW1lIjoiQWRtaW4gVXNlciIsImVtYWlsIjoiYWRtaW5AZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0.SIGNATURE"
}
```

| 字段 | 说明 |
|------|------|
| `access_token` | JWT RS256 签名的 Access Token（2 小时有效） |
| `token_type` | 固定为 `Bearer` |
| `expires_in` | Access Token 有效期（秒），7200 = 2 小时 |
| `refresh_token` | 用于获取新 Token 对的 Opaque 字符串（24 小时有效，使用时轮换） |
| `scope` | 实际授予的 scope（可能窄于请求的 scope） |
| `id_token` | OIDC ID Token（仅当 scope 包含 `openid` 且存在用户上下文时返回） |

> **注意**：响应头包含 `Cache-Control: no-store` 和 `Pragma: no-cache`，Token 响应不得被缓存。

---

### 第 6 步：调用 UserInfo 获取用户信息

使用 Access Token 调用 UserInfo Endpoint，获取用户 Claims。返回字段**严格按 scope 过滤**。

#### 请求

```bash
curl http://localhost:9096/userinfo \
  -H "Authorization: Bearer <access_token>"
```

#### 响应（scope=openid profile email）

```json
{
  "sub": "1",
  "name": "Admin User",
  "email": "admin@example.com",
  "email_verified": true
}
```

#### 响应（scope=openid）

```json
{
  "sub": "1"
}
```

> UserInfo Endpoint **要求** Access Token 包含 `openid` scope，否则返回 `invalid_scope` 错误。

---

### 第 7 步：验证 ID Token

ID Token 是 JWT RS256 签名的，你需要在本地验证其完整性和合法性。

#### ID Token Claims 结构

| Claim | 必须 | 说明 |
|-------|------|------|
| `iss` | 是 | 签发者：`http://localhost:9096` |
| `sub` | 是 | 用户标识 |
| `aud` | 是 | 受众：你的 `client_id` |
| `exp` | 是 | 过期时间 |
| `iat` | 是 | 签发时间 |
| `auth_time` | 是 | 用户完成认证的时间（Unix 时间戳） |
| `nonce` | 条件 | 第 2 步传入的 nonce（如果提供了） |
| `name` | 条件 | 仅当 scope 包含 `profile` |
| `email` | 条件 | 仅当 scope 包含 `email` |
| `email_verified` | 条件 | 仅当 scope 包含 `email` |

#### 验证步骤

1. **获取公钥**：从 `/.well-known/jwks.json` 获取 RSA 公钥
2. **验证签名**：使用 RS256 算法和公钥验证 JWT 签名
3. **验证 `iss`**：必须为 `http://localhost:9096`
4. **验证 `aud`**：必须包含你的 `client_id`
5. **验证 `exp`**：Token 不能过期
6. **验证 `nonce`**（如果提供了）：必须与第 2 步传入的 `nonce` 一致

#### Python 验证示例

```python
import jwt
import requests

# 获取 JWKS
jwks = requests.get('http://localhost:9096/.well-known/jwks.json').json()

# 解码并验证 ID Token
id_token_claims = jwt.decode(
    id_token,
    key=jwks,
    algorithms=['RS256'],
    audience='000000',       # 你的 client_id
    issuer='http://localhost:9096'
)

# 验证 nonce
if provided_nonce and id_token_claims.get('nonce') != provided_nonce:
    raise SecurityError("nonce 不匹配")

print(f"用户 ID: {id_token_claims['sub']}")
print(f"认证时间: {id_token_claims['auth_time']}")
```

---

### 第 8 步：使用 Refresh Token 刷新

Access Token 过期后（2 小时），使用 Refresh Token 获取新的 Token 对。旧 Token 对会被立即撤销。

#### 请求

```bash
curl -X POST http://localhost:9096/oauth/token \
  -u "000000:999999" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN"
```

#### 可选：缩小 Scope

```bash
curl -X POST http://localhost:9096/oauth/token \
  -u "000000:999999" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=YOUR_REFRESH_TOKEN" \
  -d "scope=openid profile"
```

> 请求的 scope **不能超过**原始授权的 scope，否则返回 `invalid_scope`。省略 `scope` 则沿用原始 scope。

#### 成功响应

与第 5 步格式相同，返回新的 `access_token`、`refresh_token` 和（如果适用）`id_token`。

> **重要**：Refresh Token 使用后**立即失效**（轮换机制）。每次返回的是全新的 Refresh Token，必须替换存储的旧值。Refresh Token 有效期为 24 小时。

---

### 第 9 步：撤销 Token

当你需要主动撤销 Token（如用户登出、安全事件），调用 Revocation Endpoint (RFC 7009)。

#### 请求

```bash
curl -X POST http://localhost:9096/oauth/revoke \
  -u "000000:999999" \
  -d "token=YOUR_ACCESS_TOKEN" \
  -d "token_type_hint=access_token"
```

#### 参数说明

| 参数 | 必须 | 说明 |
|------|------|------|
| `token` | **是** | 要撤销的 Token |
| `token_type_hint` | 否 | `access_token` 或 `refresh_token`，帮助服务器快速查找 |

> 即使 Token 不存在，也返回 `200 OK`（RFC 7009 §2.2）。撤销 Refresh Token 时，关联的 Access Token 也会被撤销。

---

### 第 10 步：登出

将用户浏览器重定向到 End Session Endpoint：

```
GET /logout?post_logout_redirect_uri=http://localhost:9094&client_id=000000
```

| 参数 | 必须 | 说明 |
|------|------|------|
| `post_logout_redirect_uri` | 否 | 登出后重定向地址，必须匹配已注册的 redirect URI |
| `client_id` | 建议 | 使用 `post_logout_redirect_uri` 时建议提供，用于验证 URI |

> 如果 `post_logout_redirect_uri` 不匹配任何已注册的客户端 URI，将重定向到 `/login`。

---

## 错误处理

### Authorization Endpoint 错误

验证 `redirect_uri` 之前的错误，以 JSON 返回（HTTP 400）：

```json
{
  "error": "invalid_client",
  "error_description": "client 999 not found"
}
```

验证 `redirect_uri` 之后的错误，通过重定向返回（RFC 6749 §4.1.2.1）：

```
HTTP/1.1 302 Found
Location: http://localhost:9094/callback?error=invalid_scope&error_description=...&state=xyz123
```

### Token Endpoint 错误

```json
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="OAuth2"
Cache-Control: no-store
Pragma: no-cache

{
  "error": "invalid_client",
  "error_description": "client authentication failed"
}
```

### 错误码一览

| 错误码 | HTTP 状态 | 说明 |
|--------|-----------|------|
| `invalid_request` | 400 | 缺少必须参数或参数不合法 |
| `invalid_client` | 401 | 客户端认证失败 |
| `invalid_grant` | 400 | Authorization Code 无效/过期/已使用/PKCE 失败/redirect_uri 不匹配 |
| `invalid_scope` | 400 | 请求的 scope 不合法或超出范围 |
| `unsupported_grant_type` | 400 | 不支持的 grant_type |
| `unsupported_response_type` | 400 | response_type 不是 `code` |
| `unauthorized_client` | 400 | 客户端未被允许使用该 grant_type |
| `access_denied` | 302 redirect | 用户拒绝授权 |

---

## 安全注意事项

1. **PKCE 是必须的** — `code_challenge` 和 `code_challenge_method=S256` 是必填参数。`plain` 方法已禁用。
2. **`code_verifier` 永远不离开客户端** — 只有 `code_challenge` 出现在 Authorization URL 中。
3. **Authorization Code 单次使用** — 交换后立即失效，1 分钟过期。
4. **`state` 参数防 CSRF** — 始终生成随机 `state`，回调时验证一致性。
5. **`nonce` 参数防重放** — 请求 ID Token 时提供 `nonce`，验证 ID Token 中的 `nonce` 一致。
6. **客户端密钥保护** — `client_secret` 仅在 Token 交换时使用（后端到后端），永远不要暴露在浏览器或前端代码中。
7. **Refresh Token 轮换** — 每次使用后旧 Token 失效，必须存储新的 Refresh Token。
8. **Token 缓存禁止** — Token 响应包含 `Cache-Control: no-store`，不可缓存。
9. **redirect_uri 精确匹配** — 必须与注册的 URI 完全一致，不允许模糊匹配或通配符。
10. **scope 最小权限原则** — 只请求必要的 scope。返回数据严格按 scope 过滤，多余的 scope 不会返回额外数据。

---

## 完整 cURL 示例

以下是一个完整的端到端流程脚本：

```bash
#!/bin/bash
set -e

SERVER="http://localhost:9096"
CLIENT_ID="000000"
CLIENT_SECRET="999999"
REDIRECT_URI="http://localhost:9094/callback"

# ─── 第 1 步：生成 PKCE ───
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '/+=' | head -c 43)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

echo "code_verifier:  $CODE_VERIFIER"
echo "code_challenge: $CODE_CHALLENGE"

# ─── 第 2 步：构造 Authorization URL ───
AUTH_URL="${SERVER}/oauth/authorize?\
response_type=code\
&client_id=${CLIENT_ID}\
&redirect_uri=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${REDIRECT_URI}'))")\
&scope=openid%20profile%20email\
&state=xyz123\
&nonce=n-0S6_WzA2Mj\
&code_challenge=${CODE_CHALLENGE}\
&code_challenge_method=S256"

echo ""
echo "在浏览器中打开此 URL 开始授权流程："
echo "$AUTH_URL"

# ─── 第 3 步：用户登录（在浏览器中完成） ───
echo ""
echo "模拟用户登录..."
LOGIN_RESP=$(curl -s -c /tmp/oauth_cookies -b /tmp/oauth_cookies -X POST "${SERVER}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}')
echo "登录响应: $LOGIN_RESP"

# ─── 用户授权 ───
echo ""
echo "提交授权同意..."
AUTH_RESP=$(curl -s -c /tmp/oauth_cookies -b /tmp/oauth_cookies -X POST "${SERVER}/api/auth" \
  -H "Content-Type: application/json" \
  -d '{"authorize":true}')
echo "授权响应: $AUTH_RESP"

# ─── 第 4 步：获取 Authorization Code ───
echo ""
echo "访问 Authorization Endpoint..."
AUTH_REDIRECT=$(curl -s -c /tmp/oauth_cookies -b /tmp/oauth_cookies -o /dev/null -w '%{redirect_url}' "$AUTH_URL")
echo "重定向 URL: $AUTH_REDIRECT"

AUTH_CODE=$(echo "$AUTH_REDIRECT" | sed 's/.*code=\([^&]*\).*/\1/')
echo "Authorization Code: $AUTH_CODE"

# ─── 第 5 步：用 Code 换取 Token ───
echo ""
echo "交换 Token..."
TOKEN_RESP=$(curl -s -X POST "${SERVER}/oauth/token" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=authorization_code" \
  -d "code=${AUTH_CODE}" \
  -d "redirect_uri=${REDIRECT_URI}" \
  -d "code_verifier=${CODE_VERIFIER}")

echo "Token 响应:"
echo "$TOKEN_RESP" | python3 -m json.tool 2>/dev/null || echo "$TOKEN_RESP"

# ─── 第 6 步：调用 UserInfo ───
ACCESS_TOKEN=$(echo "$TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -n "$ACCESS_TOKEN" ]; then
  echo ""
  echo "获取用户信息..."
  USERINFO_RESP=$(curl -s "${SERVER}/userinfo" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}")
  echo "UserInfo 响应:"
  echo "$USERINFO_RESP" | python3 -m json.tool 2>/dev/null || echo "$USERINFO_RESP"
fi

# ─── 第 9 步：撤销 Token（可选） ───
if [ -n "$ACCESS_TOKEN" ]; then
  echo ""
  echo "撤销 Access Token..."
  REVOKE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${SERVER}/oauth/revoke" \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -d "token=${ACCESS_TOKEN}" \
    -d "token_type_hint=access_token")
  echo "撤销状态码: $REVOKE_STATUS (200=成功)"
fi

# 清理
rm -f /tmp/oauth_cookies
```

---

## 附录：Discovery 文档

获取服务器配置信息：

```bash
curl http://localhost:9096/.well-known/openid-configuration
```

响应示例：

```json
{
  "issuer": "http://localhost:9096",
  "authorization_endpoint": "http://localhost:9096/oauth/authorize",
  "token_endpoint": "http://localhost:9096/oauth/token",
  "userinfo_endpoint": "http://localhost:9096/userinfo",
  "jwks_uri": "http://localhost:9096/.well-known/jwks.json",
  "end_session_endpoint": "http://localhost:9096/logout",
  "revocation_endpoint": "http://localhost:9096/oauth/revoke",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token", "password"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "email", "email_verified"],
  "code_challenge_methods_supported": ["S256"],
  "claims_parameter_supported": false
}
```
