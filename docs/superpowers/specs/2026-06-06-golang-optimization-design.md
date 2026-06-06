# Golang 代码全面优化设计

**日期**: 2026-06-06
**方案**: A（渐进式优化，4 批次）
**目标**: 代码质量 + 安全性 + 性能三维度全面优化

## 审查发现汇总

### 代码质量 + 可维护性

| # | 问题 | 文件 | 严重度 |
|---|---|---|---|
| 1 | handler.go 630 行，职责过多 | handler.go | 高 |
| 2 | Token handler 重复的 query/form fallback 代码 | handler.go:309-332 | 高 |
| 3 | 客户端认证逻辑在 Token/Revoke 中重复 | handler.go:275-294, 510-530 | 高 |
| 4 | grant.go 中 4 个 grant 方法的 token 创建代码大量重复 | grant.go | 高 |
| 5 | model.go 和 server 包有重复的 Request struct 定义 | model.go vs server/ | 中 |
| 6 | handler.UserInfo 用字符串匹配判断错误类型 | handler.go:383 | 中 |
| 7 | model.SessionData 和 service.SessionData 两处定义 | model.go:155, service/auth_service.go:22 | 中 |
| 8 | `_ = claims` 和 `_ = client` 无意义赋值 | server.go:95, 104 | 低 |
| 9 | 5 个文件未 gofmt 格式化 | gofmt 输出 | 低 |

### 安全性

| # | 问题 | 文件 | 严重度 |
|---|---|---|---|
| 1 | PKCE challenge 比较非常量时间（时序攻击风险） | pkce.go:16 | 高 |
| 2 | 密码明文存储和比较 | auth_service.go:37 | 高 |
| 3 | rand.Read 错误未检查 | store.go:162 | 中 |
| 4 | rate limiter visitors map 无上限 | middleware.go:236-248 | 中 |
| 5 | Store 无后台清理，长期运行内存泄漏 | store.go | 中 |

### 性能

| # | 问题 | 文件 | 严重度 |
|---|---|---|---|
| 1 | UserStore.GetByID() 线性遍历 O(n) | model.go:39-46 | 中 |
| 2 | scope 字符串在请求生命周期内被多次重复解析 | store.go | 低 |

---

## P0 批次：安全修复

### P0-1: PKCE constant-time 比较

**文件**: `internal/server/pkce.go`

**现状**:
```go
return computed == challenge
```

**修改为**:
```go
import "crypto/subtle"

return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
```

### P0-2: rand.Read 错误检查

**文件**: `internal/server/store.go`

**现状**:
```go
func generateRandomString(byteLen int) string {
    b := make([]byte, byteLen)
    rand.Read(b)
    return base64.RawURLEncoding.EncodeToString(b)
}
```

**修改为**:
```go
func generateRandomString(byteLen int) (string, error) {
    b := make([]byte, byteLen)
    if _, err := rand.Read(b); err != nil {
        return "", fmt.Errorf("crypto/rand: %w", err)
    }
    return base64.RawURLEncoding.EncodeToString(b), nil
}
```

**影响链**:
- `TokenGenerator.GenerateRefreshToken()` → 返回 `(string, error)`
- `TokenGenerator.GenerateAuthorizationCode()` → 返回 `(string, error)`
- 所有 4 个 grant 方法中调用 `GenerateRefreshToken()` 的地方需处理 error
- `authorizeCode()` 中调用 `GenerateAuthorizationCode()` 需处理 error

### P0-3: Rate limiter 增加上限

**文件**: `internal/middleware/middleware.go`

**修改**:
- `rateLimiter` struct 增加 `maxVisitors int` 字段
- `allow()` 方法在 `len(visitors) >= maxVisitors` 时调用 `cleanupLocked(now)` 提前清理
- 提取 `cleanupLocked(now time.Time)` 方法供 `allow()` 和 `cleanup()` 共用
- 默认 `maxVisitors = 10000`

### P0-4: Store 后台清理

**文件**: `internal/server/store.go`

**修改**:

AuthCodeStore:
- 增加 `stopCh chan struct{}`
- `NewAuthCodeStore()` 启动后台 goroutine，每 1 分钟清理过期 auth code
- 增加 `Close()` 方法优雅停止

TokenStore:
- 增加 `stopCh chan struct{}`
- `NewTokenStore()` 启动后台 goroutine，每 5 分钟清理过期 token
- 增加 `Close()` 方法优雅停止

**cmd/server/main.go**:
- 在 server 关闭前调用 `srv.AuthCodes.Close()` 和 `srv.Tokens.Close()`

---

## P1 批次：代码质量

### P1-1: 提取客户端认证辅助函数

**新文件**: `internal/handler/auth.go`

```go
var errConflictingClientID = errors.New("conflicting client_id in Authorization header and request body")

func parseClientCredentials(c *gin.Context) (clientID, clientSecret string, err error) {
    headerID, headerSecret := parseBasicAuth(c.GetHeader("Authorization"))
    bodyID := c.PostForm("client_id")
    bodySecret := c.PostForm("client_secret")
    if headerID != "" {
        if bodyID != "" && bodyID != headerID {
            return "", "", errConflictingClientID
        }
        return headerID, headerSecret, nil
    }
    return bodyID, bodySecret, nil
}
```

**影响**: Token handler 和 Revoke handler 各减少 ~15 行重复代码。

### P1-2: 消除 grant.go 中 token 创建重复代码

**文件**: `internal/server/grant.go`

提取两个辅助方法:

```go
// validateAndAuthenticate 验证客户端身份和授权类型
func (s *Server) validateAndAuthenticate(clientID, clientSecret, grantType string) (*Client, error)

// issueTokenPair 创建 access + refresh token 对并构建 TokenResponse
func (s *Server) issueTokenPair(clientID, userID, scope string, nonce string, authTime int64) (*TokenResponse, error)
```

4 个 grant 方法各自只保留核心业务差异逻辑（10-15 行）。

### P1-3: 统一错误类型

**新文件**: `internal/server/errors.go`

```go
type OAuthError struct {
    Code        string
    Description string
}

func (e *OAuthError) Error() string {
    return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func ErrInvalidClient(desc string) *OAuthError { return &OAuthError{"invalid_client", desc} }
func ErrInvalidGrant(desc string) *OAuthError  { return &OAuthError{"invalid_grant", desc} }
func ErrInvalidScope(desc string) *OAuthError  { return &OAuthError{"invalid_scope", desc} }
func ErrUnsupportedGrantType(desc string) *OAuthError { return &OAuthError{"unsupported_grant_type", desc} }
func ErrUnauthorizedClient(desc string) *OAuthError   { return &OAuthError{"unauthorized_client", desc} }
func ErrInvalidRequest(desc string) *OAuthError       { return &OAuthError{"invalid_request", desc} }
func ErrUnsupportedResponseType(desc string) *OAuthError { return &OAuthError{"unsupported_response_type", desc} }
```

**影响**:
- server 包所有 `fmt.Errorf("error_code: description")` 替换为 `ErrXxx(description)`
- handler/service 层用 `errors.As(err, &oauthErr)` 判断错误类型
- 删除 `service.ExtractOAuthError()` 字符串匹配函数
- `service.TokenError` 简化：嵌入 `*OAuthError`，只额外携带 `HTTPStatus`

### P1-4: 统一 SessionData 定义

**修改**: 删除 `model.SessionData`（未被使用），只保留 `service.SessionData`。

### P1-5: 删除 model.go 中重复的 Request struct

**修改**: 删除 `model.AuthorizeRequest`、`model.TokenRequest`、`model.AuthorizeCodeResponse`。这些类型只在 server 包有意义，model 包中的定义未被任何代码引用。

### P1-6: 清理无意义赋值

**修改**:
- `server.go:95` `_ = claims` → 直接删除这行
- `server.go:104` `_ = client` → 删除这行，client 查找用于存在性验证，赋值丢弃不必要

---

## P2 批次：可维护性

### P2-1: handler.go 拆分

**现状**: 630 行单文件

**修改**: 拆分到多个文件:

| 文件 | 内容 | 预计行数 |
|---|---|---|
| `handler.go` | Handler struct, NewHandler, readSessionData, SetupPasswordAuth | ~50 |
| `auth.go` | Login, Auth, parseClientCredentials | ~120 |
| `authorize.go` | Authorize | ~70 |
| `token.go` | Token | ~80 |
| `revoke.go` | Revoke | ~60 |
| `oidc.go` | Discovery, JWKS, UserInfo | ~60 |
| `misc.go` | HandleTokenVerify, TokenTest, Logout, parseBasicAuth | ~80 |

### P2-2: 统一请求参数回退逻辑

**新增辅助函数**:

```go
// formOrQuery 优先取 form 值，为空时回退到 query 参数
func formOrQuery(c *gin.Context, key string) string {
    if v := c.PostForm(key); v != "" {
        return v
    }
    return c.Query(key)
}
```

Token handler 中 8 个字段回退从 16 行代码变为 8 行。

### P2-3: 修复 gofmt 格式

运行 `gofmt -w .` 修复 5 个文件。

---

## P3 批次：性能 + 增强

### P3-1: UserStore 双索引

**文件**: `internal/model/model.go`

**修改**:

```go
type UserStore struct {
    mu     sync.RWMutex
    byName map[string]*User
    byID   map[string]*User
}

func NewUserStore() *UserStore {
    s := &UserStore{
        byName: make(map[string]*User),
        byID:   make(map[string]*User),
    }
    s.Set(&User{ID: "1", Username: "admin", Password: "$2a$10$...", Email: "admin@example.com", Name: "Admin User"})
    s.Set(&User{ID: "2", Username: "test", Password: "$2a$10$...", Email: "test@example.com", Name: "Test User"})
    return s
}

func (s *UserStore) Set(u *User) {
    s.mu.Lock()
    s.byName[u.Username] = u
    s.byID[u.ID] = u
    s.mu.Unlock()
}

func (s *UserStore) GetByUsername(username string) (*User, bool) {
    s.mu.RLock()
    u, ok := s.byName[username]
    s.mu.RUnlock()
    return u, ok
}

func (s *UserStore) GetByID(id string) (*User, bool) {
    s.mu.RLock()
    u, ok := s.byID[id]
    s.mu.RUnlock()
    return u, ok
}
```

`GetByID` 从 O(n) → O(1)。加 `sync.RWMutex` 保证并发安全。

### P3-2: 密码改 bcrypt

**文件**: `internal/model/model.go`, `internal/service/auth_service.go`

**修改**:

1. `User.Password` 字段存储 bcrypt hash 而非明文
2. `NewUserStore()` 中硬编码用户改为预生成的 bcrypt hash
3. `AuthService.Authenticate()` 改用 `bcrypt.CompareHashAndPassword()`

```go
// auth_service.go
import "golang.org/x/crypto/bcrypt"

func (s *AuthService) Authenticate(username, password string) (userID string, ok bool) {
    user, found := s.UserStore.GetByUsername(username)
    if !found {
        return "", false
    }
    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
        return "", false
    }
    return user.ID, true
}
```

**新增依赖**: `golang.org/x/crypto`

**注意**: Demo 用户密码仍然是 `admin`/`admin` 和 `test`/`test`，只是存储方式改变。对外 API 行为完全不变。

---

## 不在本次优化范围内

- sync.Map 改 RWMutex+map（低优先级，当前性能可接受）
- scope 解析缓存（低优先级，字符串操作开销极小）
- 动态客户端注册
- Token introspection endpoint (RFC 7662)
- 数据库持久化存储
- 单元测试（可作为后续独立任务）

## 验证标准

每个批次完成后验证:
1. `go build ./...` 编译通过
2. `go vet ./...` 无警告
3. `gofmt -l .` 无未格式化文件
4. `go test ./...` 通过（如已有测试）
5. 手动测试授权码流程核心路径
