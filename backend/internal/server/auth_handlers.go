package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/auth"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
)

// handleRegister registers a new user
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	user := &model.User{
		ID:           uuid.New().String(),
		Email:        req.Email,
		PasswordHash: hash,
		Role:         model.RoleAdmin, // Defaulting to Admin for now, restrict later
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if s.svc.DB != nil {
		if err := s.svc.DB.CreateUser(r.Context(), user); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to create user")
			return
		}
	} else {
		writeErr(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "user created"})
}

// handleLogin validates credentials and issues JWTs
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if s.svc.DB == nil {
		writeErr(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	user, err := s.svc.DB.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if !auth.CheckPasswordHash(req.Password, user.PasswordHash) {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	tokens, err := auth.GenerateTokens(user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	// Set refresh token in HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"user":         user,
		"access_token": tokens.AccessToken,
	})
}

// handleRefresh issues a new access token using an HTTP-only refresh cookie
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "missing refresh token")
		return
	}

	claims, err := auth.ValidateToken(cookie.Value)
	if err != nil || claims.Subject != "refresh" {
		writeErr(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	if s.svc.DB == nil {
		writeErr(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	user, err := s.svc.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "user not found or revoked")
		return
	}
	
	tokens, err := auth.GenerateTokens(user)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to generate tokens")
		return
	}

	// Set a new rotating refresh token
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, 
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60,
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token": tokens.AccessToken,
	})
}
