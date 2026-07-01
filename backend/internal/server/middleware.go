// Package server — HTTP middleware stack.
//
// Provides:
//   - requestLogger  — structured slog request/response logging
//   - corsMiddleware  — origin-allowlist CORS with preflight support
//   - rateLimiter     — per-IP fixed-window rate limiter (in-memory)
package server

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── Request Logger ────────────────────────────────────────────────────────────

// requestLogger logs each HTTP request and its response status/duration.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration", time.Since(start).String(),
			"ip", clientIP(r),
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

// ── CORS Middleware ───────────────────────────────────────────────────────────

// corsMiddleware handles CORS headers and OPTIONS preflight requests.
// allowedOrigins is a list of exact origins to permit (e.g. "http://localhost:5173").
func corsMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	originSet := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		originSet[strings.TrimSuffix(o, "/")] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Allow configured origins or fall back to * in dev.
			if originSet[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			} else if len(allowedOrigins) == 0 {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, PUT, PATCH, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Session-Token, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400")

			// Handle preflight.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ── Rate Limiter ──────────────────────────────────────────────────────────────

// windowEntry tracks request count for one IP within the current window.
type windowEntry struct {
	count     int
	windowEnd time.Time
}

// rateLimiter returns a fixed-window per-IP rate limiting middleware.
// limit is the max number of requests per window duration.
func rateLimiter(limit int, window time.Duration) func(http.Handler) http.Handler {
	var (
		mu      sync.Mutex
		windows = make(map[string]*windowEntry)
	)

	// Background cleanup to prevent map growth.
	go func() {
		ticker := time.NewTicker(window * 2)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			mu.Lock()
			for ip, e := range windows {
				if now.After(e.windowEnd) {
					delete(windows, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			now := time.Now()

			mu.Lock()
			e, ok := windows[ip]
			if !ok || now.After(e.windowEnd) {
				e = &windowEntry{count: 0, windowEnd: now.Add(window)}
				windows[ip] = e
			}
			e.count++
			over := e.count > limit
			mu.Unlock()

			if over {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", window.String())
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"rate limit exceeded"}`)) //nolint:errcheck
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// clientIP extracts the real client IP, honouring X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if parts := strings.Split(xff, ","); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}
