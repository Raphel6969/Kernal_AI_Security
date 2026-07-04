// Package server — Chi router and static file server.
//
// Wires every route to its handler and mounts the React frontend if
// frontend/dist/ is present on disk.  All routes are documented with
// their Python equivalents for easy cross-referencing.
package server

import (
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/config"
)

// NewRouter builds and returns the fully configured Chi router.
func NewRouter(s *Server, cfg *config.Settings) http.Handler {
	r := chi.NewRouter()

	// ── Global middleware stack ────────────────────────────────────────────────
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(requestLogger)
	r.Use(corsMiddleware(cfg.FrontendOrigins))
	r.Use(rateLimiter(200, time.Minute)) // 200 req/min per IP

	// ── Infrastructure ─────────────────────────────────────────────────────────
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)

	// ── Session ────────────────────────────────────────────────────────────────
	r.Get("/session", s.handleGetSession)

	// ── WebSocket ──────────────────────────────────────────────────────────────
	r.Get("/ws", s.handleWebSocket)

	// ── Command Analysis ───────────────────────────────────────────────────────
	// POST /analyze          → Python: POST /analyze
	// POST /analyze/llm-explain → Python: POST /analyze/llm-explain (Phase 4)
	r.Post("/analyze", s.handleAnalyze)
	r.Post("/analyze/llm-explain", s.handleAnalyzeLLMExplain)

	// ── Agent Event Ingestion ──────────────────────────────────────────────────
	// POST /agent/events     → Python: POST /agent/events
	r.Post("/agent/events", s.handleAgentEvents)

	// ── Event History ──────────────────────────────────────────────────────────
	// GET  /events           → Python: GET /events
	// DELETE /events         → Python: DELETE /events
	// GET  /events/{id}      → Python: GET /events/{event_id}
	// GET  /events/{id}/explain      → Python: GET /events/{event_id}/explain
	// POST /events/{id}/llm-explain  → Python: POST /events/{event_id}/llm-explain (Phase 4)
	r.Get("/events", s.handleGetEvents)
	r.Delete("/events", s.handleClearEvents)
	r.Get("/events/{id}", s.handleGetEvent)
	r.Get("/events/{id}/explain", s.handleGetEventExplain)
	r.Post("/events/{id}/llm-explain", s.handleEventLLMExplain)

	// ── Statistics ─────────────────────────────────────────────────────────────
	// GET /stats             → Python: GET /stats
	r.Get("/stats", s.handleGetStats)

	// ── Settings ───────────────────────────────────────────────────────────────
	// GET  /settings/thresholds   → Python: GET /settings/thresholds
	// POST /settings/thresholds   → Python: POST /settings/thresholds
	// GET  /settings/remediation  → Python: GET /settings/remediation
	// POST /settings/remediation  → Python: POST /settings/remediation
	// POST /settings/remediation/test → Python: POST /settings/remediation/test (Phase 5)
	r.Get("/settings/thresholds", s.handleGetThresholds)
	r.Post("/settings/thresholds", s.handlePostThresholds)
	r.Get("/settings/remediation", s.handleGetRemediation)
	r.Post("/settings/remediation", s.handlePostRemediation)
	r.Post("/settings/remediation/test", s.handleRemediationTest)

	// ── Webhooks (Phase 4) ─────────────────────────────────────────────────────
	r.Get("/webhooks", s.handleGetWebhooks)
	r.Post("/webhooks", s.handlePostWebhook)
	r.Delete("/webhooks/{id}", s.handleDeleteWebhook)

	// ── Authentication (Phase 5 & 6) ───────────────────────────────────────────
	r.Post("/auth/register", s.handleRegister)
	r.Post("/auth/login", s.handleLogin)
	r.Post("/auth/refresh", s.handleRefresh)
	r.Post("/auth/logout", s.handleLogout)
	r.Get("/auth/{provider}/login", s.handleOAuthLogin)
	r.Get("/auth/{provider}/callback", s.handleOAuthCallback)

	// ── Alert History (Phase 4) ────────────────────────────────────────────────
	r.Get("/alerts/history", s.handleGetAlertHistory)

	// ── Notifications (Phase 4) ────────────────────────────────────────────────
	r.Get("/notifications", s.handleGetNotifications)
	r.Post("/notifications", s.handlePostNotification)
	r.Post("/notifications/read-all", s.handleMarkAllNotificationsRead)
	r.Post("/notifications/{id}/read", s.handleMarkNotificationRead)
	r.Delete("/notifications/{id}", s.handleDeleteNotification)
	r.Delete("/notifications", s.handleClearNotifications)

	// ── Reports (Phase 4) ─────────────────────────────────────────────────────
	r.Get("/reports/departments", s.handleGetDepartments)
	r.Post("/reports/departments", s.handlePostDepartments)
	r.Post("/reports/email", s.handleSendEmailReport)

	// ── Chat (Phase 4) ────────────────────────────────────────────────────────
	r.Post("/chat", s.handleChat)

	// ── Static Frontend ───────────────────────────────────────────────────────
	// If frontend/dist/ exists, serve the React SPA.
	// The catch-all must come last so API routes take priority.
	mountFrontend(r, cfg)

	return r
}

// mountFrontend serves the React build output if it exists, otherwise
// serves a minimal API info page at /.
func mountFrontend(r *chi.Mux, cfg *config.Settings) {
	// Resolve frontend/dist relative to the module root (two directories
	// above the backend binary).
	candidates := []string{
		filepath.Join("..", "frontend", "dist"),
		filepath.Join("..", "..", "frontend", "dist"),
		"frontend/dist",
	}

	var distDir string
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			distDir = c
			break
		}
	}

	if distDir == "" {
		slog.Info("router: frontend/dist not found — serving API info at /")
		r.Get("/", apiInfoHandler(cfg))
		return
	}

	slog.Info("router: serving React frontend", "dir", distDir)
	fsys := os.DirFS(distDir)

	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Try to serve the file directly.
		name := req.URL.Path
		if name == "/" {
			name = "index.html"
		}
		name = filepath.Clean("/" + name)[1:] // strip leading /

		if _, err := fs.Stat(fsys, name); err == nil {
			http.FileServer(http.FS(fsys)).ServeHTTP(w, req)
			return
		}

		// SPA fallback: serve index.html for unknown paths.
		indexData, err := fs.ReadFile(fsys, "index.html")
		if err != nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(indexData) //nolint:errcheck
	}))
}

// apiInfoHandler serves a minimal JSON info page when the frontend is absent.
func apiInfoHandler(cfg *config.Settings) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"name":    "AEGIX Security Backend",
			"version": "go-v1.0",
			"runtime": "go",
			"docs":    "https://github.com/Raphel6969/Kernal_AI_Security",
			"routes": map[string]string{
				"healthz":    "/healthz",
				"readyz":     "/readyz",
				"session":    "/session",
				"websocket":  "/ws",
				"analyze":    "POST /analyze",
				"events":     "GET /events",
				"stats":      "GET /stats",
				"thresholds": "GET /settings/thresholds",
			},
		})
	}
}
