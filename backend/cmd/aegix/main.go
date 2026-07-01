// AEGIX Security Backend — Go entrypoint.
//
// Boot sequence:
//   1. Load config from .env / environment variables
//   2. Open SQLite hot store
//   3. Open Postgres cold store (optional — degraded gracefully if absent)
//   4. Start SyncAgent goroutine (SQLite → Postgres drain)
//   5. Load ML model → build detection pipeline
//   6. Initialise Phase 4 services (alerts, notifications, email, Groq)
//   7. Wire HTTP server (Chi router + WebSocket hub)
//   8. Serve with graceful shutdown on SIGINT / SIGTERM
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/alerts"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/chat"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/config"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/detector"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/notification"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/server"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/store"
)

func main() {
	// ── 1. Config ──────────────────────────────────────────────────────────────
	cfg := config.Load()
	setupLogger(cfg.APILogLevel)
	printBanner(cfg)

	// Root context — cancelled on shutdown to stop all background goroutines.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── 2. SQLite Hot Store ────────────────────────────────────────────────────
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
		slog.Error("failed to create data directory", "err", err)
		os.Exit(1)
	}

	hot, err := store.NewSQLiteStore(cfg.DBPath)
	if err != nil {
		slog.Error("failed to open SQLite hot store", "path", cfg.DBPath, "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := hot.Close(); err != nil {
			slog.Error("SQLite close error", "err", err)
		}
	}()
	slog.Info("✅ SQLite hot store ready", "path", cfg.DBPath)

	// ── 3. Postgres Cold Store (optional) ─────────────────────────────────────
	var cold store.ColdStore
	if cfg.DatabaseURL != "" {
		if ps, err := store.NewPostgresStore(ctx, cfg.DatabaseURL); err != nil {
			slog.Warn("⚠️  Postgres cold store unavailable — running hot-only mode", "err", err)
		} else {
			cold = ps
			defer cold.Close()
			slog.Info("✅ Postgres cold store connected")
		}
	} else {
		slog.Info("ℹ️  DATABASE_URL not set — Postgres cold store disabled")
	}

	// ── 4. Sync Agent ──────────────────────────────────────────────────────────
	var syncAgent *store.SyncAgent
	if cold != nil {
		syncAgent = store.NewSyncAgent(hot, cold, cfg.SyncIntervalSeconds, cfg.SyncBatchSize)
		syncAgent.Start()
		slog.Info("✅ SyncAgent started",
			"interval_sec", cfg.SyncIntervalSeconds,
			"batch_size", cfg.SyncBatchSize,
		)
	}

	// ── 5. Detection Pipeline ──────────────────────────────────────────────────
	// Model JSON lives alongside the SQLite DB in the data/ directory.
	modelPath := filepath.Join(filepath.Dir(cfg.DBPath), "trained_model.json")
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		// Fallback: look relative to the process CWD (useful during development).
		slog.Warn("model not found at primary path, trying fallback",
			"primary", modelPath)
		modelPath = filepath.Join("..", "data", "trained_model.json")
	}

	pipeline := detector.GetPipeline(modelPath)
	susp, mal := pipeline.GetThresholds()
	slog.Info("✅ Detection pipeline ready",
		"model_path", modelPath,
		"thresholds", fmt.Sprintf("suspicious≥%.0f malicious≥%.0f", susp, mal),
	)

	// ── 6. Phase 4 Services ────────────────────────────────────────────────────
	alertManager := alerts.NewAlertManager()

	notifStore := notification.NewNotificationStore()

	emailService := notification.NewEmailService(cfg)
	if emailService.IsConfigured() {
		slog.Info("✅ Gmail SMTP configured", "user", cfg.GmailUser)
	} else {
		slog.Info("ℹ️  Gmail SMTP not configured — email reports disabled")
	}

	groqClient := chat.NewGroqClient(cfg.GroqAPIKey, cfg.GroqModel, cfg.GroqTimeoutSeconds)
	if groqClient.IsConfigured() {
		slog.Info("✅ Groq LLM configured", "model", cfg.GroqModel)
	} else {
		slog.Info("ℹ️  GROQ_API_KEY not set — LLM explain and chat use fallback responses")
	}

	svc := server.Services{
		Alerts:        alertManager,
		Notifications: notifStore,
		Email:         emailService,
		Groq:          groqClient,
	}

	// ── 7. HTTP Server ─────────────────────────────────────────────────────────
	srv := server.NewServer(cfg, hot, pipeline, svc)
	router := server.NewRouter(srv, cfg)

	addr := fmt.Sprintf("%s:%d", cfg.APIHost, cfg.APIPort)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Start serving in a goroutine so we can handle shutdown signals.
	serverErr := make(chan error, 1)
	go func() {
		slog.Info("🚀 AEGIX listening", "addr", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// ── 8. Graceful Shutdown ───────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		slog.Info("shutdown signal received", "signal", sig.String())
	case err := <-serverErr:
		slog.Error("server error — initiating shutdown", "err", err)
	}

	// Cancel root context and stop SyncAgent.
	cancel()
	if syncAgent != nil {
		syncAgent.Stop()
	}

	slog.Info("draining HTTP connections (30s timeout)...")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutCancel()

	if err := httpServer.Shutdown(shutCtx); err != nil {
		slog.Error("forced shutdown after timeout", "err", err)
	}

	slog.Info("AEGIX stopped cleanly. 👋")
}

// ── Startup helpers ───────────────────────────────────────────────────────────

// setupLogger configures the global slog handler based on the log-level string.
func setupLogger(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     lvl,
		AddSource: lvl == slog.LevelDebug,
	})
	slog.SetDefault(slog.New(handler))
}

// printBanner logs the startup banner with key configuration values.
func printBanner(cfg *config.Settings) {
	fmt.Fprintf(os.Stdout, `
╔══════════════════════════════════════════════════════╗
║          🛡  AEGIX Security Backend  🛡              ║
║          Runtime: Go  |  Enterprise Edition          ║
╠══════════════════════════════════════════════════════╣
║  Port        : %-37d║
║  Log Level   : %-37s║
║  Session Mode: %-37v║
║  Postgres    : %-37s║
╚══════════════════════════════════════════════════════╝
`,
		cfg.APIPort,
		cfg.APILogLevel,
		cfg.SessionMode,
		func() string {
			if cfg.DatabaseURL != "" {
				return "enabled"
			}
			return "disabled (hot-only)"
		}(),
	)
}
