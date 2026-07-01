// Package server — HTTP handlers, Server struct, and session store.
//
// Services bundles all Phase 4 dependencies.
// All Phase 3 stubs are replaced with real implementations here.
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

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/alerts"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/chat"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/config"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/detector"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/notification"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/store"
)

// Prevent unused import for chat package.
var _ = chat.ChatMessage{}

// ── Services ──────────────────────────────────────────────────────────────────

// Services bundles Phase 4 external dependencies injected into the Server.
type Services struct {
	Alerts        *alerts.AlertManager
	Notifications *notification.NotificationStore
	Email         *notification.EmailService
	Groq          *chat.GroqClient // used for both explain AND chat
}

// ── Server ────────────────────────────────────────────────────────────────────

// Server holds all handler dependencies and is the central wiring point
// for the HTTP layer.
type Server struct {
	cfg      *config.Settings
	hot      store.HotStore
	pipeline *detector.Pipeline
	hub      *Hub
	sessions *sessionStore
	svc      Services

	remMu       sync.RWMutex
	remediation remediationConfig
}

// remediationConfig holds runtime remediation settings.
type remediationConfig struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
	Signal  string `json:"signal"`
}

// NewServer constructs a fully wired Server and starts the WebSocket hub.
func NewServer(
	cfg *config.Settings,
	hot store.HotStore,
	pipeline *detector.Pipeline,
	svc Services,
) *Server {
	s := &Server{
		cfg:      cfg,
		hot:      hot,
		pipeline: pipeline,
		hub:      NewHub(),
		sessions: newSessionStore(time.Duration(cfg.SessionTTL) * time.Second),
		svc:      svc,
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
	s := &sessionStore{sessions: make(map[string]sessionEntry), ttl: ttl}
	go s.cleanup()
	return s
}

func (ss *sessionStore) Create() (token, sessionID string) {
	tb, sb := make([]byte, 32), make([]byte, 16)
	rand.Read(tb) //nolint:errcheck
	rand.Read(sb) //nolint:errcheck
	token, sessionID = hex.EncodeToString(tb), hex.EncodeToString(sb)
	ss.mu.Lock()
	ss.sessions[token] = sessionEntry{sessionID: sessionID, expiresAt: time.Now().Add(ss.ttl)}
	ss.mu.Unlock()
	return
}

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

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy", "version": "go-v1.0"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if _, err := s.hot.Size(nil, nil); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// ── Session ───────────────────────────────────────────────────────────────────

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	token, sessionID := s.sessions.Create()
	writeJSON(w, http.StatusOK, map[string]string{
		"session_token": token,
		"session_id":    sessionID,
	})
}

// ── Analysis ─────────────────────────────────────────────────────────────────

type analyzeRequest struct {
	Command             string  `json:"command"`
	AgentID             *string `json:"agent_id"`
	SessionID           *string `json:"session_id"`
	ProcessMemoryMB     float64 `json:"process_memory_mb"`
	SystemMemoryPercent float64 `json:"system_memory_percent"`
}

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
	if s.cfg.SessionMode {
		if sid := s.sessionFromRequest(r); sid != nil {
			req.SessionID = sid
		}
	}

	event := s.buildAndStoreEvent(req.Command, req.AgentID, req.SessionID,
		0, 0, 0, 0, "", "", req.ProcessMemoryMB, req.SystemMemoryPercent, unixNow())
	if event == nil {
		writeErr(w, http.StatusInternalServerError, "failed to store event")
		return
	}

	s.postProcess(event)
	writeJSON(w, http.StatusOK, event.Flatten())
}

// POST /analyze/llm-explain — one-shot Groq explanation without storing.
func (s *Server) handleAnalyzeLLMExplain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Command        string   `json:"command"`
		Classification string   `json:"classification"`
		RiskScore      float64  `json:"risk_score"`
		MatchedRules   []string `json:"matched_rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	explanation := s.groqExplain(req.Command, req.Classification, req.RiskScore, req.MatchedRules)
	writeJSON(w, http.StatusOK, map[string]string{"llm_explanation": explanation})
}

// ── Agent Events ──────────────────────────────────────────────────────────────

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

func (s *Server) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	var req agentEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ts := req.Timestamp
	if ts == 0 {
		ts = unixNow()
	}

	event := s.buildAndStoreEvent(req.Command, req.AgentID, req.SessionID,
		req.PID, req.PPID, req.UID, req.GID,
		req.ArgvStr, req.Comm,
		req.ProcessMemoryMB, req.SystemMemoryPercent, ts)
	if event == nil {
		writeErr(w, http.StatusInternalServerError, "failed to store event")
		return
	}

	s.postProcess(event)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "event_id": event.ID})
}

// ── Event History ─────────────────────────────────────────────────────────────

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	agentID := queryString(r, "agent_id")
	sessionID := s.resolveSession(r)

	events, err := s.hot.GetRecent(limit, agentID, sessionID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to fetch events")
		return
	}
	flat := make([]map[string]any, len(events))
	for i, e := range events {
		flat[i] = e.Flatten()
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": flat, "count": len(flat)})
}

func (s *Server) handleClearEvents(w http.ResponseWriter, r *http.Request) {
	if err := s.hot.Clear(s.resolveSession(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to clear events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	event, err := s.hot.GetEvent(id, s.resolveSession(r))
	if err != nil || event == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("event %q not found", id))
		return
	}
	writeJSON(w, http.StatusOK, event.Flatten())
}

func (s *Server) handleGetEventExplain(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	event, err := s.hot.GetEvent(id, s.resolveSession(r))
	if err != nil || event == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("event %q not found", id))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"event":       event.Flatten(),
		"explanation": event.DetectionResult.Explanation,
	})
}

// POST /events/{id}/llm-explain — call Groq, persist, and broadcast.
func (s *Server) handleEventLLMExplain(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	event, err := s.hot.GetEvent(id, nil)
	if err != nil || event == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("event %q not found", id))
		return
	}

	explanation := s.groqExplain(
		event.ExecveEvent.Command,
		event.DetectionResult.Classification,
		event.DetectionResult.RiskScore,
		event.DetectionResult.MatchedRules,
	)

	// Persist and broadcast the updated event.
	if err := s.hot.UpdateLLMExplanation(id, explanation); err != nil {
		slog.Warn("handleEventLLMExplain: UpdateLLMExplanation", "err", err)
	}
	event.DetectionResult.LLMExplanation = explanation
	s.hub.BroadcastEvent(event)

	writeJSON(w, http.StatusOK, map[string]string{
		"event_id":        id,
		"llm_explanation": explanation,
	})
}

// ── Stats ─────────────────────────────────────────────────────────────────────

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
		"risk_score_avg": 0.0,
	})
}

// ── Settings ──────────────────────────────────────────────────────────────────

func (s *Server) handleGetThresholds(w http.ResponseWriter, r *http.Request) {
	susp, mal := s.pipeline.GetThresholds()
	writeJSON(w, http.StatusOK, map[string]float64{
		"suspicious_threshold": susp,
		"malicious_threshold":  mal,
	})
}

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

func (s *Server) handleGetRemediation(w http.ResponseWriter, r *http.Request) {
	s.remMu.RLock()
	rem := s.remediation
	s.remMu.RUnlock()
	writeJSON(w, http.StatusOK, rem)
}

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

func (s *Server) handleRemediationTest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"result": "Remediation test is implemented in Phase 5.",
	})
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("ws: upgrade", "err", err)
		return
	}
	sessionID := s.sessionFromRequest(r)
	client := &Client{hub: s.hub, conn: conn, send: make(chan []byte, 256), sessionID: sessionID}
	s.hub.register <- client
	go s.replayEvents(client, sessionID)
	go client.writePump()
	client.readPump()
}

func (s *Server) replayEvents(client *Client, sessionID *string) {
	events, err := s.hot.GetRecent(100, nil, sessionID)
	if err != nil {
		return
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	for _, event := range events {
		payload, err := json.Marshal(map[string]any{"type": "replay_event", "event": event.Flatten()})
		if err != nil {
			continue
		}
		select {
		case client.send <- payload:
		default:
			return
		}
	}
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

func (s *Server) handleGetWebhooks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": s.svc.Alerts.ListWebhooks()})
}

func (s *Server) handlePostWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL               string `json:"url"`
		TriggerSafe       bool   `json:"trigger_safe"`
		TriggerSuspicious bool   `json:"trigger_suspicious"`
		TriggerMalicious  bool   `json:"trigger_malicious"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	wh, err := s.svc.Alerts.AddWebhook(req.URL, req.TriggerSafe, req.TriggerSuspicious, req.TriggerMalicious)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Notify via WebSocket
	s.hub.BroadcastRaw(mustMarshal(map[string]any{"type": "webhook_added", "webhook": wh}))
	writeJSON(w, http.StatusCreated, wh)
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !s.svc.Alerts.RemoveWebhook(id) {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("webhook %q not found", id))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Alert History ─────────────────────────────────────────────────────────────

func (s *Server) handleGetAlertHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"alerts": s.svc.Alerts.GetHistory()})
}

// ── Notifications ─────────────────────────────────────────────────────────────

func (s *Server) handleGetNotifications(w http.ResponseWriter, r *http.Request) {
	sid := s.resolveSession(r)
	items := s.svc.Notifications.List(sid)
	writeJSON(w, http.StatusOK, map[string]any{
		"notifications": items,
		"unread_count":  s.svc.Notifications.UnreadCount(sid),
	})
}

func (s *Server) handlePostNotification(w http.ResponseWriter, r *http.Request) {
	var n model.Notification
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	n.SessionID = s.resolveSession(r)
	s.svc.Notifications.Add(&n)
	writeJSON(w, http.StatusCreated, n)
}

func (s *Server) handleMarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.svc.Notifications.MarkRead(id, s.resolveSession(r)); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	s.svc.Notifications.MarkAllRead(s.resolveSession(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteNotification(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.svc.Notifications.Delete(id, s.resolveSession(r)); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleClearNotifications(w http.ResponseWriter, r *http.Request) {
	s.svc.Notifications.Clear(s.resolveSession(r))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ── Reports / Departments ─────────────────────────────────────────────────────

func (s *Server) handleGetDepartments(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"departments": s.svc.Notifications.GetDepartments()})
}

func (s *Server) handlePostDepartments(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Departments []model.Department `json:"departments"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.svc.Notifications.SetDepartments(req.Departments)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "departments": req.Departments})
}

func (s *Server) handleSendEmailReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Format     string   `json:"format"`
		EventLimit int      `json:"event_limit"`
		ExtraTo    []string `json:"extra_to"`
		SessionID  *string  `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Format == "" {
		req.Format = "html"
	}
	limit := req.EventLimit
	if limit <= 0 {
		limit = 100
	}

	sid := s.resolveSession(r)
	if req.SessionID != nil {
		sid = req.SessionID
	}
	events, _ := s.hot.GetRecent(limit, nil, sid)

	depts := s.svc.Notifications.GetDepartments()
	if err := s.svc.Email.SendReport(events, req.Format, depts, req.ExtraTo); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"message":    fmt.Sprintf("Report sent to %d department(s)", len(depts)+len(req.ExtraTo)),
		"event_count": len(events),
	})
}

// ── Chat ──────────────────────────────────────────────────────────────────────

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string             `json:"message"`
		History []chat.ChatMessage `json:"history"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		writeErr(w, http.StatusBadRequest, "message must not be empty")
		return
	}

	response, err := s.svc.Groq.Chat(req.Message, req.History)
	if err != nil {
		slog.Error("handleChat: groq", "err", err)
		response = "I encountered an error. Please try again."
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"response": response,
		"type":     "text",
	})
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// buildAndStoreEvent runs detection, creates a SecurityEvent, and appends it to
// the hot store.  Returns nil on storage failure.
func (s *Server) buildAndStoreEvent(
	command string,
	agentID, sessionID *string,
	pid, ppid, uid, gid int64,
	argvStr, comm string,
	processMem, systemMem float64,
	ts float64,
) *model.SecurityEvent {
	result := s.pipeline.Detect(command, processMem, systemMem)
	event := &model.SecurityEvent{
		ID: newEventID(),
		ExecveEvent: model.ExecveEvent{
			PID:                 pid,
			PPID:                ppid,
			UID:                 uid,
			GID:                 gid,
			Command:             command,
			ArgvStr:             argvStr,
			Comm:                comm,
			Timestamp:           ts,
			ProcessMemoryMB:     processMem,
			SystemMemoryPercent: systemMem,
			AgentID:             agentID,
			SessionID:           sessionID,
		},
		DetectionResult: *result,
		DetectedAt:      unixNow(),
	}
	if err := s.hot.Append(event); err != nil {
		slog.Error("buildAndStoreEvent: Append", "err", err)
		return nil
	}
	return event
}

// postProcess runs after every new event: WebSocket broadcast, alert dispatch,
// and automatic notification creation.
func (s *Server) postProcess(event *model.SecurityEvent) {
	s.hub.BroadcastEvent(event)

	if s.svc.Alerts != nil {
		s.svc.Alerts.DispatchAsync(event)
	}

	if s.svc.Notifications != nil {
		s.maybeCreateNotification(event)
	}
}

// maybeCreateNotification auto-creates a notification for suspicious/malicious events.
func (s *Server) maybeCreateNotification(event *model.SecurityEvent) {
	cls := event.DetectionResult.Classification
	if cls == "safe" {
		return
	}
	title := "⚠️ Suspicious Command Detected"
	if cls == "malicious" {
		title = "🚨 Malicious Command Detected"
	}
	s.svc.Notifications.Add(&model.Notification{
		Category:  "logs",
		Title:     title,
		Message:   fmt.Sprintf("%s | Risk: %.0f%%", truncate(event.ExecveEvent.Command, 60), event.DetectionResult.RiskScore),
		SessionID: event.ExecveEvent.SessionID,
	})
}

// groqExplain calls the Groq client if configured, otherwise returns a graceful empty string.
func (s *Server) groqExplain(command, classification string, riskScore float64, rules []string) string {
	if s.svc.Groq == nil {
		return ""
	}
	expl, _ := s.svc.Groq.Explain(command, classification, riskScore, rules)
	return expl
}

// sessionFromRequest extracts a validated sessionID from the request.
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

// resolveSession returns the session filter for store queries.
func (s *Server) resolveSession(r *http.Request) *string {
	if s.cfg.SessionMode {
		return s.sessionFromRequest(r)
	}
	return queryString(r, "session_id")
}

// ── Utility ───────────────────────────────────────────────────────────────────

func newEventID() string {
	return "evt_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:8]
}

func unixNow() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON encode", "err", err)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func queryString(r *http.Request, key string) *string {
	if v := r.URL.Query().Get(key); v != "" {
		return &v
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// Prevent unused import.
var _ = fmt.Sprintf
