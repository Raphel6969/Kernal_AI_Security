// Package server — HTTP handlers, Server struct, and session store.
//
// The Server struct holds all dependencies and exposes handler methods.
// Phase 3 implements all core endpoints fully; Phase 4 handlers are stubbed
// with correct response shapes so the React frontend works immediately.
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/config"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/detector"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/store"
)

// ── Server ────────────────────────────────────────────────────────────────────

// Server holds all handler dependencies and is the central wiring point
// for the HTTP layer.
type Server struct {
	cfg      *config.Settings
	hot      store.HotStore
	pipeline *detector.Pipeline
	hub      *Hub
	sessions *sessionStore

	// Remediation settings (in-memory, protected by mutex)
	remMu       sync.RWMutex
	remediation remediationConfig
}

// remediationConfig holds runtime remediation settings.
type remediationConfig struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
	Signal  string `json:"signal"`
}

// NewServer constructs a Server and starts the WebSocket hub.
func NewServer(
	cfg *config.Settings,
	hot store.HotStore,
	pipeline *detector.Pipeline,
) *Server {
	s := &Server{
		cfg:      cfg,
		hot:      hot,
		pipeline: pipeline,
		hub:      NewHub(),
		sessions: newSessionStore(time.Duration(cfg.SessionTTL) * time.Second),
		remediation: remediationConfig{
			Enabled: false,
			Mode:    "kill",
			Signal:  "SIGKILL",
		},
	}
	go s.hub.Run()
	return s
}

// ── Session Store ─────────────────────────────────────────────────────────────

type sessionEntry struct {
	sessionID string
	expiresAt time.Time
}

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry
	ttl      time.Duration
}

func newSessionStore(ttl time.Duration) *sessionStore {
	if ttl <= 0 {
		ttl = time.Hour
	}
	s := &sessionStore{
		sessions: make(map[string]sessionEntry),
		ttl:      ttl,
	}
	go s.cleanup()
	return s
}

// Create generates a new (token, sessionID) pair and stores it.
func (ss *sessionStore) Create() (token, sessionID string) {
	tb := make([]byte, 32)
	sb := make([]byte, 16)
	rand.Read(tb) //nolint:errcheck
	rand.Read(sb) //nolint:errcheck
	token = hex.EncodeToString(tb)
	sessionID = hex.EncodeToString(sb)

	ss.mu.Lock()
	ss.sessions[token] = sessionEntry{sessionID: sessionID, expiresAt: time.Now().Add(ss.ttl)}
	ss.mu.Unlock()
	return
}

// Validate returns the sessionID if the token is valid and not expired.
func (ss *sessionStore) Validate(token string) (sessionID string, ok bool) {
	ss.mu.RLock()
	entry, found := ss.sessions[token]
	ss.mu.RUnlock()
	if !found || time.Now().After(entry.expiresAt) {
		ss.mu.Lock()
		delete(ss.sessions, token)
		ss.mu.Unlock()
		return "", false
	}
	return entry.sessionID, true
}

func (ss *sessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		ss.mu.Lock()
		for t, e := range ss.sessions {
			if now.After(e.expiresAt) {
				delete(ss.sessions, t)
			}
		}
		ss.mu.Unlock()
	}
}

// ── Health ────────────────────────────────────────────────────────────────────

// GET /healthz — always healthy if the process is running.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"version": "go-v1.0",
	})
}

// GET /readyz — healthy only when the SQLite store is accessible.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	_, err := s.hot.Size(nil, nil)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not_ready",
			"error":  err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// ── Session ───────────────────────────────────────────────────────────────────

// GET /session — creates a new session token and returns it.
func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	token, sessionID := s.sessions.Create()
	writeJSON(w, http.StatusOK, map[string]string{
		"session_token": token,
		"session_id":    sessionID,
	})
}

// ── Analysis ─────────────────────────────────────────────────────────────────

// analyzeRequest is the JSON body for POST /analyze.
type analyzeRequest struct {
	Command             string  `json:"command"`
	AgentID             *string `json:"agent_id"`
	SessionID           *string `json:"session_id"`
	ProcessMemoryMB     float64 `json:"process_memory_mb"`
	SystemMemoryPercent float64 `json:"system_memory_percent"`
}

// POST /analyze — runs the detection pipeline and stores the result.
func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	var req analyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		writeErr(w, http.StatusBadRequest, "command must not be empty")
		return
	}

	// Override session from header/query if session mode is active.
	if s.cfg.SessionMode {
		if sid := s.sessionFromRequest(r); sid != nil {
			req.SessionID = sid
		}
	}

	result := s.pipeline.Detect(req.Command, req.ProcessMemoryMB, req.SystemMemoryPercent)

	now := unixNow()
	event := &model.SecurityEvent{
		ID: newEventID(),
		ExecveEvent: model.ExecveEvent{
			Command:             req.Command,
			AgentID:             req.AgentID,
			SessionID:           req.SessionID,
			Timestamp:           now,
			ProcessMemoryMB:     req.ProcessMemoryMB,
			SystemMemoryPercent: req.SystemMemoryPercent,
		},
		DetectionResult: *result,
		DetectedAt:      now,
	}

	if err := s.hot.Append(event); err != nil {
		slog.Error("handleAnalyze: store append", "err", err)
		writeErr(w, http.StatusInternalServerError, "failed to store event")
		return
	}

	s.hub.BroadcastEvent(event)
	writeJSON(w, http.StatusOK, event.Flatten())
}

// POST /analyze/llm-explain — Tier C Groq explanation (Phase 4).
func (s *Server) handleAnalyzeLLMExplain(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"explanation": "LLM explanations are implemented in Phase 4.",
	})
}

// ── Agent Events ──────────────────────────────────────────────────────────────

// agentEventRequest is the JSON body for POST /agent/events.
type agentEventRequest struct {
	Command             string  `json:"command"`
	PID                 int64   `json:"pid"`
	PPID                int64   `json:"ppid"`
	UID                 int64   `json:"uid"`
	GID                 int64   `json:"gid"`
	ArgvStr             string  `json:"argv_str"`
	Comm                string  `json:"comm"`
	Timestamp           float64 `json:"timestamp"`
	ProcessMemoryMB     float64 `json:"process_memory_mb"`
	SystemMemoryPercent float64 `json:"system_memory_percent"`
	AgentID             *string `json:"agent_id"`
	SessionID           *string `json:"session_id"`
}

// POST /agent/events — ingests an execve event from a remote eBPF agent.
func (s *Server) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	var req agentEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result := s.pipeline.Detect(req.Command, req.ProcessMemoryMB, req.SystemMemoryPercent)

	now := unixNow()
	ts := req.Timestamp
	if ts == 0 {
		ts = now
	}

	event := &model.SecurityEvent{
		ID: newEventID(),
		ExecveEvent: model.ExecveEvent{
			PID:                 req.PID,
			PPID:                req.PPID,
			UID:                 req.UID,
			GID:                 req.GID,
			Command:             req.Command,
			ArgvStr:             req.ArgvStr,
			Comm:                req.Comm,
			Timestamp:           ts,
			ProcessMemoryMB:     req.ProcessMemoryMB,
			SystemMemoryPercent: req.SystemMemoryPercent,
			AgentID:             req.AgentID,
			SessionID:           req.SessionID,
		},
		DetectionResult: *result,
		DetectedAt:      now,
	}

	if err := s.hot.Append(event); err != nil {
		slog.Error("handleAgentEvents: store append", "err", err)
		writeErr(w, http.StatusInternalServerError, "failed to store event")
		return
	}

	s.hub.BroadcastEvent(event)

	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "ok",
		"event_id": event.ID,
	})
}

// ── Event History ─────────────────────────────────────────────────────────────

// GET /events — returns recent events from the hot store.
func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	agentID := queryString(r, "agent_id")
	sessionID := s.resolveSession(r)

	events, err := s.hot.GetRecent(limit, agentID, sessionID)
	if err != nil {
		slog.Error("handleGetEvents: GetRecent", "err", err)
		writeErr(w, http.StatusInternalServerError, "failed to fetch events")
		return
	}

	flat := make([]map[string]any, len(events))
	for i, e := range events {
		flat[i] = e.Flatten()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": flat,
		"count":  len(flat),
	})
}

// DELETE /events — clears event history.
func (s *Server) handleClearEvents(w http.ResponseWriter, r *http.Request) {
	sessionID := s.resolveSession(r)
	if err := s.hot.Clear(sessionID); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to clear events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GET /events/{id} — fetches a single event.
func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sessionID := s.resolveSession(r)

	event, err := s.hot.GetEvent(id, sessionID)
	if err != nil || event == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("event %q not found", id))
		return
	}
	writeJSON(w, http.StatusOK, event.Flatten())
}

// GET /events/{id}/explain — returns the rule explanation for an event.
func (s *Server) handleGetEventExplain(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sessionID := s.resolveSession(r)

	event, err := s.hot.GetEvent(id, sessionID)
	if err != nil || event == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("event %q not found", id))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"event":       event.Flatten(),
		"explanation": event.DetectionResult.Explanation,
	})
}

// POST /events/{id}/llm-explain — async Groq explanation (Phase 4 stub).
func (s *Server) handleEventLLMExplain(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	writeJSON(w, http.StatusOK, map[string]string{
		"event_id":    id,
		"explanation": "LLM explanations are implemented in Phase 4.",
	})
}

// ── Stats ─────────────────────────────────────────────────────────────────────

// GET /stats — returns event classification counts.
func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	agentID := queryString(r, "agent_id")
	sessionID := s.resolveSession(r)

	total, _ := s.hot.Size(sessionID, agentID)
	safe, _ := s.hot.CountByClassification("safe", agentID, sessionID)
	suspicious, _ := s.hot.CountByClassification("suspicious", agentID, sessionID)
	malicious, _ := s.hot.CountByClassification("malicious", agentID, sessionID)

	writeJSON(w, http.StatusOK, map[string]any{
		"total":          total,
		"safe":           safe,
		"suspicious":     suspicious,
		"malicious":      malicious,
		"risk_score_avg": 0.0, // TODO: aggregate in store
	})
}

// ── Settings: Thresholds ──────────────────────────────────────────────────────

// GET /settings/thresholds — returns current detection thresholds.
func (s *Server) handleGetThresholds(w http.ResponseWriter, r *http.Request) {
	susp, mal := s.pipeline.GetThresholds()
	writeJSON(w, http.StatusOK, map[string]float64{
		"suspicious_threshold": susp,
		"malicious_threshold":  mal,
	})
}

// POST /settings/thresholds — updates detection thresholds at runtime.
func (s *Server) handlePostThresholds(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Suspicious float64 `json:"suspicious_threshold"`
		Malicious  float64 `json:"malicious_threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Suspicious <= 0 || req.Malicious <= 0 || req.Suspicious >= req.Malicious {
		writeErr(w, http.StatusBadRequest, "suspicious must be > 0 and < malicious")
		return
	}
	s.pipeline.UpdateThresholds(req.Suspicious, req.Malicious)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":               "ok",
		"suspicious_threshold": req.Suspicious,
		"malicious_threshold":  req.Malicious,
	})
}

// ── Settings: Remediation ─────────────────────────────────────────────────────

// GET /settings/remediation — returns current remediation settings.
func (s *Server) handleGetRemediation(w http.ResponseWriter, r *http.Request) {
	s.remMu.RLock()
	rem := s.remediation
	s.remMu.RUnlock()
	writeJSON(w, http.StatusOK, rem)
}

// POST /settings/remediation — updates remediation settings.
func (s *Server) handlePostRemediation(w http.ResponseWriter, r *http.Request) {
	var req remediationConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.remMu.Lock()
	s.remediation = req
	s.remMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "settings": req})
}

// POST /settings/remediation/test — tests remediation on a PID (Phase 5 stub).
func (s *Server) handleRemediationTest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"result": "Remediation test is implemented in Phase 5.",
	})
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

// GET /ws — upgrades the connection to WebSocket.
// Replays the last 100 events to the new client immediately after connecting.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("ws: upgrade", "err", err)
		return
	}

	sessionID := s.sessionFromRequest(r)
	client := &Client{
		hub:       s.hub,
		conn:      conn,
		send:      make(chan []byte, 256),
		sessionID: sessionID,
	}
	s.hub.register <- client

	// Replay last 100 events before starting pumps.
	go s.replayEvents(client, sessionID)

	go client.writePump()
	client.readPump()
}

// replayEvents sends the last 100 stored events to a newly connected client.
func (s *Server) replayEvents(client *Client, sessionID *string) {
	events, err := s.hot.GetRecent(100, nil, sessionID)
	if err != nil {
		slog.Error("ws: replay GetRecent", "err", err)
		return
	}

	// Events come back newest-first; reverse for chronological order.
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	for _, event := range events {
		payload, err := json.Marshal(map[string]any{
			"type":  "replay_event",
			"event": event.Flatten(),
		})
		if err != nil {
			continue
		}
		select {
		case client.send <- payload:
		default:
			return // client's buffer full
		}
	}
}

// ── Phase 4 Stubs ─────────────────────────────────────────────────────────────
// These return the correct response shapes so the frontend doesn't break.
// Full implementations land in Phase 4.

func (s *Server) handleGetWebhooks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": []any{}})
}

func (s *Server) handlePostWebhook(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "message": "Webhooks implemented in Phase 4."})
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleGetAlertHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"alerts": []any{}})
}

func (s *Server) handleGetNotifications(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"notifications": []any{}, "unread_count": 0})
}

func (s *Server) handlePostNotification(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteNotification(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleClearNotifications(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleGetDepartments(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"departments": []any{}})
}

func (s *Server) handlePostDepartments(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSendEmailReport(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "Email reports are implemented in Phase 4.",
	})
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"response": "AI chat is implemented in Phase 4.",
		"type":     "text",
	})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// sessionFromRequest extracts a session ID from X-Session-Token header or
// session_token query param when session mode is active.
func (s *Server) sessionFromRequest(r *http.Request) *string {
	if !s.cfg.SessionMode {
		return nil
	}
	token := r.Header.Get("X-Session-Token")
	if token == "" {
		token = r.URL.Query().Get("session_token")
	}
	if token == "" {
		return nil
	}
	sessionID, ok := s.sessions.Validate(token)
	if !ok {
		return nil
	}
	return &sessionID
}

// resolveSession returns the session ID for filtering — from the request
// when session mode is active, or from the query param "session_id" directly.
func (s *Server) resolveSession(r *http.Request) *string {
	if s.cfg.SessionMode {
		return s.sessionFromRequest(r)
	}
	return queryString(r, "session_id")
}

// newEventID generates a short event ID in the same format as the Python backend.
// Format: "evt_" + first 8 hex chars of a UUID (e.g., "evt_550e8400").
func newEventID() string {
	return "evt_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:8]
}

// unixNow returns the current Unix timestamp as a float64 with sub-second precision.
func unixNow() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// writeJSON writes a JSON response with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON encode", "err", err)
	}
}

// writeErr writes a standard JSON error response.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// queryInt reads an integer query parameter, returning def if missing or invalid.
func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// queryString reads a string query parameter, returning nil if missing.
func queryString(r *http.Request, key string) *string {
	if v := r.URL.Query().Get(key); v != "" {
		return &v
	}
	return nil
}

// Prevent unused import errors for fmt package.
var _ = fmt.Sprintf
