package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/auth"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
)

var (
	oauthStateCookieName = "oauthstate"
)

func getOAuthConfig(provider string) (*oauth2.Config, error) {
	callbackURL := "http://localhost:8000/api/auth/" + provider + "/callback"
	
	switch provider {
	case "google":
		return &oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  callbackURL,
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
			Endpoint:     google.Endpoint,
		}, nil
	case "github":
		return &oauth2.Config{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			RedirectURL:  callbackURL,
			Scopes:       []string{"user:email"},
			Endpoint:     github.Endpoint,
		}, nil
	default:
		return nil, fmt.Errorf("provider %s not supported", provider)
	}
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{
		Name:     oauthStateCookieName,
		Value:    state,
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)
	return state
}

func (s *Server) handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	conf, err := getOAuthConfig(provider)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	state := generateStateOauthCookie(w)
	url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	
	// Validate state
	stateCookie, err := r.Cookie(oauthStateCookieName)
	if err != nil || r.FormValue("state") != stateCookie.Value {
		writeErr(w, http.StatusBadRequest, "invalid oauth state")
		return
	}

	conf, err := getOAuthConfig(provider)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	code := r.FormValue("code")
	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to exchange token")
		return
	}

	// Fetch user info based on provider
	var email, providerID string
	client := conf.Client(context.Background(), token)

	if provider == "google" {
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to get user info")
			return
		}
		defer resp.Body.Close()
		
		var user struct {
			Id    string `json:"id"`
			Email string `json:"email"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to parse user info")
			return
		}
		email = user.Email
		providerID = user.Id
	} else if provider == "github" {
		// Get User ID
		resp, err := client.Get("https://api.github.com/user")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to get github user")
			return
		}
		defer resp.Body.Close()
		
		var ghUser struct {
			Id int64 `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&ghUser); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to parse github user")
			return
		}
		providerID = fmt.Sprintf("%d", ghUser.Id)

		// Get Primary Email
		emailResp, err := client.Get("https://api.github.com/user/emails")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to get github emails")
			return
		}
		defer emailResp.Body.Close()

		var emails []struct {
			Email   string `json:"email"`
			Primary bool   `json:"primary"`
		}
		if err := json.NewDecoder(emailResp.Body).Decode(&emails); err == nil {
			for _, e := range emails {
				if e.Primary {
					email = e.Email
					break
				}
			}
		}
	}

	if email == "" || providerID == "" {
		writeErr(w, http.StatusBadRequest, "failed to extract email or id from provider")
		return
	}

	// Upsert User in DB
	user := &model.User{
		ID:           uuid.New().String(),
		Email:        email,
		PasswordHash: "", // No password for OAuth
		Provider:     provider,
		ProviderID:   providerID,
		Role:         model.RoleViewer, // Default role
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if s.svc.DB != nil {
		if err := s.svc.DB.UpsertOAuthUser(r.Context(), user); err != nil {
			slog.Error("Failed to upsert OAuth user", "error", err)
			writeErr(w, http.StatusInternalServerError, "failed to save user")
			return
		}
	}

	// Generate JWT Tokens
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

	// Redirect to frontend where the auth interceptor will automatically refresh token
	// Read frontend origins to find the correct redirect URL, default to localhost:5173
	redirectURL := "http://localhost:5173"
	if s.cfg.FrontendOrigins != nil && len(s.cfg.FrontendOrigins) > 0 {
		redirectURL = s.cfg.FrontendOrigins[0]
	}
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}
