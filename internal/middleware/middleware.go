package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-session/session/v3"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
)

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
	mu       sync.Mutex
	visitors map[string]*visitorInfo
	limit    int
	window   time.Duration
}

type visitorInfo struct {
	count   int
	resetAt time.Time
}

// RateLimit limits requests per IP within a time window. Returns 429 when exceeded.
func RateLimit(limit int, window time.Duration) gin.HandlerFunc {
	rl := &rateLimiter{
		visitors: make(map[string]*visitorInfo),
		limit:    limit,
		window:   window,
	}
	go rl.cleanup()
	return func(c *gin.Context) {
		key := c.ClientIP()
		if !rl.allow(key) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, model.ErrorResponse{
				Error:             "slow_down",
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
		rl.visitors[key] = &visitorInfo{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	v.count++
	return v.count <= rl.limit
}

func (rl *rateLimiter) cleanup() {
	for {
		time.Sleep(rl.window)
		rl.mu.Lock()
		now := time.Now()
		for k, v := range rl.visitors {
			if now.After(v.resetAt) {
				delete(rl.visitors, k)
			}
		}
		rl.mu.Unlock()
	}
}
