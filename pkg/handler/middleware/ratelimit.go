package middleware

import (
	"fmt"
	"net"
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

// ipToKey returns the client IP to key the rate limiter on: the host part of
// r.RemoteAddr (the raw TCP peer address, which a client can't spoof), with
// the port stripped -- the port is different on every new TCP connection, so
// keying on the full host:port (as this used to) let a client reset its own
// bucket just by not reusing a connection. It must not re-read
// True-Client-IP/X-Real-IP/X-Forwarded-For itself, since an unauthenticated
// client can set any of those to an arbitrary value and get a fresh
// rate-limit bucket on every request. chi's RealIP middleware overwrites
// r.RemoteAddr from those same headers, so it's only registered upstream
// (see Handler's default middleware chain) when Cfg.TrustProxyHeaders
// confirms ezauth sits behind a reverse proxy that sanitizes them first.
func ipToKey(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
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
		used := entry.used
		remaining := rl.cfg.Requests - used
		if remaining < 0 {
			remaining = 0
		}
		resetUnix := entry.expiresAt.Unix()

		rl.mu.Unlock()

		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rl.cfg.Requests))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetUnix))

		if used > rl.cfg.Requests {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(rl.cfg.Window.Seconds())))
			http.Error(w, "429 too many requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
