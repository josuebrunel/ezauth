package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type windowEntry struct {
	expiresAt time.Time
	used      int
}

type RateLimiter struct {
	mu      sync.Mutex
	windows map[string]*windowEntry
	cfg     RateLimitConfig
}

type RateLimitConfig struct {
	Enabled    bool
	Requests   int
	Window     time.Duration
	ByClientIP bool
}

func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		windows: make(map[string]*windowEntry),
		cfg:     cfg,
	}
	if cfg.Enabled {
		go rl.cleanupLoop()
	}
	return rl
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cfg.Window)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, entry := range rl.windows {
			if now.After(entry.expiresAt) {
				delete(rl.windows, key)
			}
		}
		rl.mu.Unlock()
	}
}

func ipToKey(r *http.Request) string {
	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ip = fwd
	}
	return ip
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		var key string
		if rl.cfg.ByClientIP {
			key = ipToKey(r)
		} else {
			key = ""
		}

		rl.mu.Lock()
		now := time.Now()
		entry, exists := rl.windows[key]
		if !exists || now.After(entry.expiresAt) {
			entry = &windowEntry{
				expiresAt: now.Add(rl.cfg.Window),
				used:      0,
			}
			rl.windows[key] = entry
		}

		entry.used++
		remaining := rl.cfg.Requests - entry.used
		if remaining < 0 {
			remaining = 0
		}
		resetUnix := entry.expiresAt.Unix()

		rl.mu.Unlock()

		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.cfg.Requests))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetUnix))

		if entry.used > rl.cfg.Requests {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rl.cfg.Window.Seconds())))
			http.Error(w, "429 too many requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
