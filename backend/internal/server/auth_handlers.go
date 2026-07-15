package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/auth"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
)

type RegisterRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"secret123"`
}

type LoginRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"secret123"`
}

// handleRegister registers a new user
//	@Summary		Register User
//	@Description	Create a new user account with email and password
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		RegisterRequest	true	"Registration details"
//	@Success		201		{object}	map[string]string
//	@Failure		400		{object}	map[string]string
//	@Failure		500		{object}	map[string]string
//	@Router			/auth/register [post]
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
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
			if strings.Contains(err.Error(), "SQLSTATE 23505") {
				writeErr(w, http.StatusConflict, "email already registered")
				return
			}
			slog.Error("failed to create user in db", "error", err, "email", req.Email)
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
//	@Summary		Login User
//	@Description	Authenticate user and return access token + HTTP-only refresh cookie
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		LoginRequest	true	"Login details"
//	@Success		200		{object}	map[string]any
//	@Failure		400		{object}	map[string]string
//	@Failure		401		{object}	map[string]string
//	@Failure		503		{object}	map[string]string
//	@Router			/auth/login [post]
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
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
//	@Summary		Refresh Access Token
//	@Description	Uses the HTTP-only refresh_token cookie to issue a new access token
//	@Tags			Auth
//	@Produce		json
//	@Success		200		{object}	map[string]any
//	@Failure		401		{object}	map[string]string
//	@Failure		503		{object}	map[string]string
//	@Router			/auth/refresh [post]
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

	writeJSON(w, http.StatusOK, map[string]any{
		"user":         user,
		"access_token": tokens.AccessToken,
	})
}

// handleLogout clears the HTTP-only refresh cookie
//	@Summary		Logout User
//	@Description	Clears the HTTP-only refresh_token cookie
//	@Tags			Auth
//	@Produce		json
//	@Success		200		"Logged out successfully"
//	@Router			/auth/logout [post]
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusOK)
}
