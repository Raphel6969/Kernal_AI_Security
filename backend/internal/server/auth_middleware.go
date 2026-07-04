package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/auth"
)

type contextKey string

const (
	UserContextKey contextKey = "user_claims"
)

// requireAuth is a middleware that enforces JWT authentication.
func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeErr(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			writeErr(w, http.StatusUnauthorized, "invalid authorization format")
			return
		}

		tokenString := parts[1]
		claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			// Specific error for expiration so the frontend interceptor knows to refresh
			if strings.Contains(err.Error(), "token is expired") {
				writeErr(w, http.StatusUnauthorized, "token expired")
			} else {
				writeErr(w, http.StatusUnauthorized, "invalid token")
			}
			return
		}

		// Inject claims into request context
		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
