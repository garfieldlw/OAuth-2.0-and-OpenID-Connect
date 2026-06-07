package middleware

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowUnderLimit(t *testing.T) {
	rl := &rateLimiter{
		visitors:    make(map[string]*visitorInfo),
		limit:       3,
		window:      time.Minute,
		maxVisitors: 10000,
	}

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// 4th request should be denied
	if rl.allow("1.2.3.4") {
		t.Fatal("4th request should be denied")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := &rateLimiter{
		visitors:    make(map[string]*visitorInfo),
		limit:       2,
		window:      time.Minute,
		maxVisitors: 10000,
	}

	// Use up the limit for IP 1
	rl.allow("1.1.1.1")
	rl.allow("1.1.1.1")
	if rl.allow("1.1.1.1") {
		t.Fatal("3rd request from IP 1 should be denied")
	}

	// IP 2 should have its own independent limit
	if !rl.allow("2.2.2.2") {
		t.Fatal("1st request from IP 2 should be allowed")
	}
	if !rl.allow("2.2.2.2") {
		t.Fatal("2nd request from IP 2 should be allowed")
	}
	if rl.allow("2.2.2.2") {
		t.Fatal("3rd request from IP 2 should be denied")
	}
}

func TestRateLimiter_MaxVisitorsCleanup(t *testing.T) {
	rl := &rateLimiter{
		visitors:    make(map[string]*visitorInfo),
		limit:       10,
		window:      100 * time.Millisecond,
		maxVisitors: 3,
	}

	// Add 3 visitors to fill up to maxVisitors
	rl.allow("1.1.1.1")
	rl.allow("2.2.2.2")
	rl.allow("3.3.3.3")

	if len(rl.visitors) != 3 {
		t.Fatalf("expected 3 visitors, got %d", len(rl.visitors))
	}

	// Wait for the window to expire so entries become eligible for cleanup
	time.Sleep(150 * time.Millisecond)

	// Adding a 4th visitor should trigger cleanupLocked and succeed
	// (expired entries are removed, making room)
	if !rl.allow("4.4.4.4") {
		t.Fatal("4th visitor should be allowed after cleanup of expired entries")
	}

	// The expired entries should have been cleaned up; only the new visitor remains
	if len(rl.visitors) != 1 {
		t.Fatalf("expected 1 visitor after cleanup, got %d", len(rl.visitors))
	}

	// Verify the remaining visitor is the new one
	if _, ok := rl.visitors["4.4.4.4"]; !ok {
		t.Fatal("expected visitor 4.4.4.4 to exist after cleanup")
	}
}
