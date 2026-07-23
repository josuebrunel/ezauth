package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_Disabled(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{Enabled: false})
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRateLimiter_Headers(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		Enabled:    true,
		Requests:   5,
		Window:     time.Minute,
		ByClientIP: true,
	})
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if v := rec.Header().Get("X-RateLimit-Limit"); v != "5" {
		t.Errorf("expected X-RateLimit-Limit=5, got %q", v)
	}
	if v := rec.Header().Get("X-RateLimit-Remaining"); v != "4" {
		t.Errorf("expected X-RateLimit-Remaining=4, got %q", v)
	}
	if v := rec.Header().Get("X-RateLimit-Reset"); v == "" {
		t.Error("expected X-RateLimit-Reset to be set")
	}
}

func TestRateLimiter_BlockAfterLimit(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		Enabled:    true,
		Requests:   2,
		Window:     time.Minute,
		ByClientIP: true,
	})
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.2:12345"

	// First request — allowed
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", rec.Code)
	}

	// Second request — allowed
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("second request: expected 200, got %d", rec.Code)
	}

	// Third request — blocked
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("third request: expected 429, got %d", rec.Code)
	}
	if v := rec.Header().Get("Retry-After"); v == "" {
		t.Error("expected Retry-After header on 429")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		Enabled:    true,
		Requests:   1,
		Window:     time.Minute,
		ByClientIP: true,
	})
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request from IP A — allowed
	reqA := httptest.NewRequest("GET", "/", nil)
	reqA.RemoteAddr = "192.0.2.3:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, reqA)
	if rec.Code != http.StatusOK {
		t.Errorf("IP A first: expected 200, got %d", rec.Code)
	}

	// Request from IP B — allowed (different bucket)
	reqB := httptest.NewRequest("GET", "/", nil)
	reqB.RemoteAddr = "192.0.2.4:12345"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, reqB)
	if rec.Code != http.StatusOK {
		t.Errorf("IP B first: expected 200, got %d", rec.Code)
	}

	// Request from IP A again — blocked
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, reqA)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("IP A second: expected 429, got %d", rec.Code)
	}
}

func TestRateLimiter_ConcurrentSafe(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		Enabled:    true,
		Requests:   1000,
		Window:     time.Minute,
		ByClientIP: true,
	})
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	errs := make(chan error, 500)
	for range 50 {
		go func() {
			for range 10 {
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = "192.0.2.5:12345"
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code == http.StatusTooManyRequests {
					errs <- fmt.Errorf("unexpected 429 under load")
					return
				}
			}
			errs <- nil
		}()
	}
	for range 50 {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
}

func TestRateLimiter_ByClientIPFalse(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		Enabled:    true,
		Requests:   1,
		Window:     time.Minute,
		ByClientIP: false,
	})
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request from IP A
	reqA := httptest.NewRequest("GET", "/", nil)
	reqA.RemoteAddr = "192.0.2.6:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, reqA)
	if rec.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", rec.Code)
	}

	// Second request from IP B (same global bucket)
	reqB := httptest.NewRequest("GET", "/", nil)
	reqB.RemoteAddr = "192.0.2.7:12345"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, reqB)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request (different IP, same bucket): expected 429, got %d", rec.Code)
	}
}
