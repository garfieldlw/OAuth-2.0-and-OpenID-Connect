package middleware

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

// sensitiveFormKeys are redacted in log output to prevent credential leakage.
var sensitiveFormKeys = map[string]bool{
	"client_secret":    true,
	"password":         true,
	"code_verifier":    true,
	"refresh_token":    true,
	"access_token":     true,
	"client_secret_id": true,
}

// CORS sets Cross-Origin Resource Sharing headers.
// Allowed origins: http://localhost:5173 (Vite dev), http://localhost:9096 (server).
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		allowedOrigins := map[string]bool{
			"http://localhost:5173": true,
			"http://localhost:9096": true,
		}
		if allowedOrigins[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// Session ensures a server-side session is started for every request.
func Session() gin.HandlerFunc {
	return func(c *gin.Context) {
		session.Start(c.Request.Context(), c.Writer, c.Request)
		c.Next()
	}
}

type rateLimiter struct {
	mu          sync.Mutex
	visitors    map[string]*visitorInfo
	limit       int
	window      time.Duration
	maxVisitors int
}

type visitorInfo struct {
	count   int
	resetAt time.Time
}

// RateLimit limits requests per IP within a time window. Returns 429 when exceeded.
func RateLimit(limit int, window time.Duration) gin.HandlerFunc {
	rl := &rateLimiter{
		visitors:    make(map[string]*visitorInfo),
		limit:       limit,
		window:      window,
		maxVisitors: 10000,
	}
	go rl.cleanup()
	return func(c *gin.Context) {
		key := c.ClientIP()
		if !rl.allow(key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, model.ErrorResponse{
				Error:            "slow_down",
				ErrorDescription: "rate limit exceeded, try again later",
			})
			return
		}
		c.Next()
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	v, ok := rl.visitors[key]
	if !ok || now.After(v.resetAt) {
		if len(rl.visitors) >= rl.maxVisitors {
			rl.cleanupLocked(now)
		}
		rl.visitors[key] = &visitorInfo{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	v.count++
	return v.count <= rl.limit
}

// RequestLogger returns a gin middleware that logs every request as a structured
// JSON line to the standard logger. Each entry contains:
//
//	timestamp, request_id, method, path, query, protocol, status,
//	latency_ms, latency_ns, client_ip, user_agent, referer,
//	content_type, content_length, response_size,
//	request_body (JSON), form_data (POST form, sensitive keys redacted)
//
// The request_id is a random 16-byte base64url string set on every incoming
// request. If the client sends an X-Request-ID header it is used instead.
// Sensitive fields (client_secret, password, code_verifier, etc.) are
// redacted to prevent credential leakage in logs.
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		contentType := c.ContentType()
		var requestBody interface{}
		var formData url.Values

		switch {
		case strings.HasPrefix(contentType, "application/json"):
			bodyBytes, err := io.ReadAll(c.Request.Body)
			if err == nil && len(bodyBytes) > 0 {
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				var parsed interface{}
				if json.Unmarshal(bodyBytes, &parsed) == nil {
					requestBody = redactJSON(parsed)
				} else {
					requestBody = string(bodyBytes)
				}
			}
		case strings.HasPrefix(contentType, "application/x-www-form-urlencoded"):
			if err := c.Request.ParseForm(); err == nil {
				formData = redactForm(c.Request.Form)
			}
		}

		c.Next()

		latency := time.Since(start)
		entry := map[string]interface{}{
			"timestamp":      start.UTC().Format(time.RFC3339Nano),
			"request_id":     requestID,
			"method":         c.Request.Method,
			"path":           c.Request.URL.Path,
			"query":          c.Request.URL.RawQuery,
			"protocol":       c.Request.Proto,
			"status":         c.Writer.Status(),
			"latency_ms":     latency.Seconds() * 1000,
			"latency_ns":     latency.Nanoseconds(),
			"client_ip":      c.ClientIP(),
			"user_agent":     c.Request.UserAgent(),
			"referer":        c.GetHeader("Referer"),
			"content_type":   contentType,
			"content_length": c.Request.ContentLength,
			"response_size":  c.Writer.Size(),
		}

		if requestBody != nil {
			entry["request_body"] = requestBody
		}
		if formData != nil {
			entry["form_data"] = formData
		}
		if len(c.Errors) > 0 {
			entry["gin_errors"] = c.Errors.String()
		}

		data, _ := json.Marshal(entry)
		log.Println(string(data))
	}
}

// redactForm returns a copy of form values with sensitive keys replaced by "[REDACTED]".
func redactForm(form url.Values) url.Values {
	result := make(url.Values, len(form))
	for k, v := range form {
		if sensitiveFormKeys[k] {
			result[k] = []string{"[REDACTED]"}
		} else {
			result[k] = v
		}
	}
	return result
}

// redactJSON returns a copy of a parsed JSON value with sensitive keys replaced by "[REDACTED]".
func redactJSON(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, v := range val {
			if sensitiveFormKeys[k] {
				result[k] = "[REDACTED]"
			} else {
				result[k] = redactJSON(v)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, elem := range val {
			result[i] = redactJSON(elem)
		}
		return result
	default:
		return v
	}
}

// generateRequestID creates a random 16-byte base64url string.
func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (rl *rateLimiter) cleanupLocked(now time.Time) {
	for k, v := range rl.visitors {
		if now.After(v.resetAt) {
			delete(rl.visitors, k)
		}
	}
}

func (rl *rateLimiter) cleanup() {
	for {
		time.Sleep(rl.window)
		rl.mu.Lock()
		rl.cleanupLocked(time.Now())
		rl.mu.Unlock()
	}
}
