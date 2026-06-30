// Package config loads and exposes all application settings from environment
// variables and the project-root .env file.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Settings holds every configuration value needed by the Aegix backend.
// Fields map 1-to-1 with the Python Settings class so existing .env files
// require no changes.
type Settings struct {
	// ── HTTP Server ──────────────────────────────────────────────────────────
	APIHost     string
	APIPort     int
	APILogLevel string

	// ── CORS ─────────────────────────────────────────────────────────────────
	FrontendOrigins []string // parsed from comma-separated FRONTEND_ORIGINS

	// ── Database ─────────────────────────────────────────────────────────────
	DBPath      string // SQLite hot-cache path (absolute)
	DatabaseURL string // Postgres DSN — if empty, Postgres is disabled

	EventCacheSize int

	// ── Session ──────────────────────────────────────────────────────────────
	SessionMode bool
	SessionTTL  int    // seconds until a session is flushed from SQLite
	SecretKey   string // HMAC-SHA256 key for session token signing

	// ── Kernel Monitor ───────────────────────────────────────────────────────
	KernelMonitorOwner string // "backend" | "agent" | "disabled"

	// ── Agent ────────────────────────────────────────────────────────────────
	BackendURL        string
	AgentEventTimeout int

	// ── Gmail SMTP ───────────────────────────────────────────────────────────
	GmailUser        string
	GmailAppPassword string
	GmailFromEmail   string
	GmailSMTPHost    string
	GmailSMTPPort    int
	DepartmentEmails string // raw JSON map, parsed downstream

	// ── Groq LLM (Tier C explainer) ──────────────────────────────────────────
	GroqAPIKey         string
	GroqModel          string
	GroqTimeoutSeconds int

	// ── Gemini (chatbot) ─────────────────────────────────────────────────────
	GeminiAPIKey    string
	GeminiChatModel string

	// ── Sync Agent (new — Go specific) ───────────────────────────────────────
	SyncIntervalSeconds int // how often the SQLite→Postgres drain runs
	SyncBatchSize       int // max events per drain cycle
}

// singleton
var instance *Settings

// Load reads environment variables (and the nearest .env file) and returns a
// fully initialised Settings.  It is idempotent — calling it a second time
// returns the cached value.
func Load() *Settings {
	if instance != nil {
		return instance
	}

	// Try to load a .env from the project root (various CWD scenarios).
	for _, candidate := range envFileCandidates() {
		if err := godotenv.Load(candidate); err == nil {
			slog.Info("config: loaded .env", "path", candidate)
			break
		}
	}

	s := &Settings{
		APIHost:     env("API_HOST", "0.0.0.0"),
		APIPort:     envInt("API_PORT", 8000),
		APILogLevel: env("API_LOG_LEVEL", "info"),

		FrontendOrigins: parseCSV(env(
			"FRONTEND_ORIGINS",
			"http://localhost:5173,http://127.0.0.1:5173",
		)),

		DBPath:         resolveDBPath(env("DB_PATH", "")),
		DatabaseURL:    env("DATABASE_URL", ""),
		EventCacheSize: envInt("EVENT_CACHE_SIZE", 1000),

		SessionMode: envBool("SESSION_MODE", false),
		SessionTTL:  envInt("SESSION_TTL", 3600),
		SecretKey:   env("SECRET_KEY", ""),

		KernelMonitorOwner: env("KERNEL_MONITOR_OWNER", "backend"),

		BackendURL:        env("BACKEND_URL", "http://localhost:8000"),
		AgentEventTimeout: envInt("AGENT_EVENT_TIMEOUT", 5),

		GmailUser:        env("GMAIL_USER", ""),
		GmailAppPassword: env("GMAIL_APP_PASSWORD", ""),
		GmailFromEmail:   env("GMAIL_FROM_EMAIL", ""),
		GmailSMTPHost:    env("GMAIL_SMTP_HOST", "smtp.gmail.com"),
		GmailSMTPPort:    envInt("GMAIL_SMTP_PORT", 587),
		DepartmentEmails: env("DEPARTMENT_EMAILS", ""),

		GroqAPIKey:         env("GROQ_API_KEY", ""),
		GroqModel:          env("GROQ_MODEL", "llama-3.3-70b-versatile"),
		GroqTimeoutSeconds: envInt("GROQ_TIMEOUT_SECONDS", 30),

		GeminiAPIKey:    env("GEMINI_API_KEY", ""),
		GeminiChatModel: env("GEMINI_CHAT_MODEL", "gemini-flash-latest"),

		SyncIntervalSeconds: envInt("SYNC_INTERVAL_SECONDS", 5),
		SyncBatchSize:       envInt("SYNC_BATCH_SIZE", 100),
	}

	// Ensure a secret key exists (persist to disk so restarts reuse the same key).
	if s.SecretKey == "" {
		s.SecretKey = loadOrGenerateSecret(s.DBPath)
	}

	instance = s
	return s
}

// Get returns the cached Settings, loading if necessary.
func Get() *Settings {
	if instance != nil {
		return instance
	}
	return Load()
}

// ValidateOwner returns a normalised kernel monitor owner value.
func (s *Settings) ValidateOwner() string {
	switch strings.ToLower(s.KernelMonitorOwner) {
	case "backend", "agent", "disabled":
		return strings.ToLower(s.KernelMonitorOwner)
	default:
		slog.Warn("config: invalid KERNEL_MONITOR_OWNER, falling back to 'backend'",
			"value", s.KernelMonitorOwner)
		return "backend"
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func parseCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// resolveDBPath turns a raw path (possibly empty or relative) into an absolute
// path, defaulting to <project-root>/data/events.db.
func resolveDBPath(raw string) string {
	if raw == "" {
		raw = filepath.Join(projectRoot(), "data", "events.db")
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return raw
	}
	return abs
}

// projectRoot walks up from the current file's location to find the repo root.
func projectRoot() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	// internal/config/config.go → backend → project root
	return filepath.Join(filepath.Dir(filename), "..", "..", "..", "..")
}

// envFileCandidates returns paths to try when loading .env.
func envFileCandidates() []string {
	root := projectRoot()
	return []string{
		filepath.Join(root, ".env"),
		".env",
		"../.env",
		"../../.env",
	}
}

// loadOrGenerateSecret tries to read a persisted secret from
// <data-dir>/.session_secret, generating and persisting one if missing.
func loadOrGenerateSecret(dbPath string) string {
	secretPath := filepath.Join(filepath.Dir(dbPath), ".session_secret")

	if data, err := os.ReadFile(secretPath); err == nil {
		if s := strings.TrimSpace(string(data)); s != "" {
			return s
		}
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback — should never happen
		return hex.EncodeToString([]byte("aegix-fallback-secret-key-unsafe"))
	}
	secret := hex.EncodeToString(b)

	_ = os.MkdirAll(filepath.Dir(secretPath), 0o700)
	_ = os.WriteFile(secretPath, []byte(secret), 0o600)

	return secret
}
