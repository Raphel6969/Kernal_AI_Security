// Package model defines all shared domain types used across the Aegix backend.
// Structs mirror the Python dataclasses exactly so JSON output to the React
// frontend remains byte-compatible with the existing API contract.
package model

import (
	"encoding/json"
	"time"
)

// ── Core security-event types ─────────────────────────────────────────────────

// ExecveEvent is a single execve syscall captured by the eBPF hook or API.
type ExecveEvent struct {
	PID                 int64   `json:"pid"`
	PPID                int64   `json:"ppid"`
	UID                 int64   `json:"uid"`
	GID                 int64   `json:"gid"`
	Command             string  `json:"command"`
	ArgvStr             string  `json:"argv_str"`
	Timestamp           float64 `json:"timestamp"`
	Comm                string  `json:"comm"`
	ProcessMemoryMB     float64 `json:"process_memory_mb"`
	SystemMemoryPercent float64 `json:"system_memory_percent"`
	AgentID             *string `json:"agent_id,omitempty"`
	SessionID           *string `json:"session_id,omitempty"`
}

// DetectionResult holds the output of the detection pipeline for one command.
type DetectionResult struct {
	RiskScore      float64  `json:"risk_score"`      // 0–100
	Classification string   `json:"classification"`  // "safe" | "suspicious" | "malicious"
	MatchedRules   []string `json:"matched_rules"`
	MLConfidence   float64  `json:"ml_confidence"`   // 0–1
	Explanation    string   `json:"explanation"`     // Tier A/B rule explanation
	LLMExplanation string   `json:"llm_explanation"` // Tier C Groq explanation (async)
}

// SecurityEvent is the combined record stored in both SQLite and Postgres.
type SecurityEvent struct {
	ID                string          `json:"id"`           // "evt_<hex8>"
	ExecveEvent       ExecveEvent     `json:"execve_event"`
	DetectionResult   DetectionResult `json:"detection_result"`
	DetectedAt        float64         `json:"detected_at"` // Unix timestamp
	RemediationAction *string         `json:"remediation_action,omitempty"`
	RemediationStatus *string         `json:"remediation_status,omitempty"`
}

// Flatten returns the flat dict the React dashboard expects — identical to the
// Python SecurityEvent.dict() output.
func (e *SecurityEvent) Flatten() map[string]any {
	return map[string]any{
		"id":                    e.ID,
		"agent_id":              e.ExecveEvent.AgentID,
		"session_id":            e.ExecveEvent.SessionID,
		"pid":                   e.ExecveEvent.PID,
		"ppid":                  e.ExecveEvent.PPID,
		"uid":                   e.ExecveEvent.UID,
		"gid":                   e.ExecveEvent.GID,
		"command":               e.ExecveEvent.Command,
		"argv_str":              e.ExecveEvent.ArgvStr,
		"timestamp":             e.ExecveEvent.Timestamp,
		"comm":                  e.ExecveEvent.Comm,
		"risk_score":            e.DetectionResult.RiskScore,
		"classification":        e.DetectionResult.Classification,
		"matched_rules":         e.DetectionResult.MatchedRules,
		"ml_confidence":         e.DetectionResult.MLConfidence,
		"explanation":           e.DetectionResult.Explanation,
		"llm_explanation":       e.DetectionResult.LLMExplanation,
		"detected_at":           e.DetectedAt,
		"remediation_action":    e.RemediationAction,
		"remediation_status":    e.RemediationStatus,
		"process_memory_mb":     e.ExecveEvent.ProcessMemoryMB,
		"system_memory_percent": e.ExecveEvent.SystemMemoryPercent,
	}
}

// ── Webhook / alert types ─────────────────────────────────────────────────────

// Webhook is a registered alert endpoint.
type Webhook struct {
	ID                string    `json:"id"`
	URL               string    `json:"url"`
	TriggerSafe       bool      `json:"trigger_safe"`
	TriggerSuspicious bool      `json:"trigger_suspicious"`
	TriggerMalicious  bool      `json:"trigger_malicious"`
	CreatedAt         time.Time `json:"created_at"`
}

// AlertHistory records one webhook dispatch attempt.
type AlertHistory struct {
	ID             string    `json:"id"`
	WebhookID      string    `json:"webhook_id"`
	WebhookURL     string    `json:"webhook_url"`
	EventID        string    `json:"event_id"`
	Classification string    `json:"classification"`
	StatusCode     int       `json:"status_code"`
	Success        bool      `json:"success"`
	Error          string    `json:"error,omitempty"`
	DispatchedAt   time.Time `json:"dispatched_at"`
}

// ── Notification types ────────────────────────────────────────────────────────

// Notification is a user-facing dashboard notification.
type Notification struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"` // "webhook"|"email"|"logs"|"settings"
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	Read      bool      `json:"read"`
	SessionID *string   `json:"session_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Department maps a department name to an alert email address.
type Department struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// ── Helper functions ──────────────────────────────────────────────────────────

// MarshalRules serialises a rules slice to a JSON string for database storage.
func MarshalRules(rules []string) string {
	if len(rules) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(rules)
	return string(b)
}

// UnmarshalRules parses a JSON string back to []string.  Returns an empty
// slice on any error so callers never have to deal with nil.
func UnmarshalRules(s string) []string {
	var rules []string
	if s == "" {
		return rules
	}
	_ = json.Unmarshal([]byte(s), &rules)
	if rules == nil {
		rules = []string{}
	}
	return rules
}

// PtrString returns a *string from a plain string (nil if empty).
func PtrString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// DerefString safely dereferences a *string, returning "" if nil.
func DerefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
