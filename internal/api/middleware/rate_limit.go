package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) func(http.Handler) http.Handler {
	rl := &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}

	// Background eviction of old entries
	go func() {
		ticker := time.NewTicker(window * 2)
		for range ticker.C {
			rl.mu.Lock()
			now := time.Now()
			for k, timestamps := range rl.requests {
				var valid []time.Time
				for _, t := range timestamps {
					if now.Sub(t) <= window {
						valid = append(valid, t)
					}
				}
				if len(valid) == 0 {
					delete(rl.requests, k)
				} else {
					rl.requests[k] = valid
				}
			}
			rl.mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := extractClientKey(r)

			rl.mu.Lock()
			now := time.Now()
			timestamps := rl.requests[key]

			var active []time.Time
			for _, t := range timestamps {
				if now.Sub(t) <= window {
					active = append(active, t)
				}
			}

			if len(active) >= limit {
				rl.mu.Unlock()
				respondRateLimited(w, r)
				return
			}

			rl.requests[key] = append(active, now)
			rl.mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

func extractClientKey(r *http.Request) string {
	claims := GetClaims(r.Context())
	if claims != nil && claims.Email != "" {
		return "user:" + claims.Email
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip = strings.TrimSpace(parts[0])
	}
	return "ip:" + ip
}

func respondRateLimited(w http.ResponseWriter, r *http.Request) {
	reqID, _ := r.Context().Value(RequestIDKey).(string)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":       "RATE_LIMITED",
			"message":    "Rate limit exceeded. Please retry later.",
			"request_id": reqID,
		},
	})
}
