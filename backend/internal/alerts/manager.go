// Package alerts — webhook registry, async dispatch, and alert history.
//
// AlertManager is safe for concurrent use.
//
// Dispatch flow:
//   1. An event arrives via Server.handleAnalyze or Server.handleAgentEvents
//   2. Server calls manager.DispatchAsync(event)
//   3. One goroutine per matching webhook fires an HTTP POST
//   4. Result (status code, error) is appended to the in-memory history ring
package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
)

const (
	maxHistory      = 500
	dispatchTimeout = 10 * time.Second
)

// AlertManager stores webhooks and alert history in memory and
// dispatches alerts asynchronously.
type AlertManager struct {
	mu       sync.RWMutex
	webhooks []model.Webhook
	history  []model.AlertHistory
	client   *http.Client
}

// NewAlertManager constructs an AlertManager with a shared HTTP client.
func NewAlertManager() *AlertManager {
	return &AlertManager{
		client: &http.Client{Timeout: dispatchTimeout},
	}
}

// ── Webhook registry ──────────────────────────────────────────────────────────

// AddWebhook registers a new webhook and returns it.
func (am *AlertManager) AddWebhook(
	rawURL string,
	triggerSafe, triggerSuspicious, triggerMalicious bool,
) (*model.Webhook, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("webhook URL must not be empty")
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return nil, fmt.Errorf("webhook URL must start with http:// or https://")
	}

	wh := model.Webhook{
		ID:                "wh_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:8],
		URL:               rawURL,
		TriggerSafe:       triggerSafe,
		TriggerSuspicious: triggerSuspicious,
		TriggerMalicious:  triggerMalicious,
		CreatedAt:         time.Now(),
	}

	am.mu.Lock()
	am.webhooks = append(am.webhooks, wh)
	am.mu.Unlock()

	slog.Info("alerts: webhook registered", "id", wh.ID, "url", wh.URL)
	return &wh, nil
}

// RemoveWebhook deletes a webhook by ID. Returns false if not found.
func (am *AlertManager) RemoveWebhook(id string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	for i, wh := range am.webhooks {
		if wh.ID == id {
			am.webhooks = append(am.webhooks[:i], am.webhooks[i+1:]...)
			slog.Info("alerts: webhook removed", "id", id)
			return true
		}
	}
	return false
}

// ListWebhooks returns a copy of the current webhook list.
func (am *AlertManager) ListWebhooks() []model.Webhook {
	am.mu.RLock()
	defer am.mu.RUnlock()
	if len(am.webhooks) == 0 {
		return []model.Webhook{}
	}
	out := make([]model.Webhook, len(am.webhooks))
	copy(out, am.webhooks)
	return out
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

// DispatchAsync fires HTTP POSTs to all matching webhooks in background goroutines.
// It does not block the caller.
func (am *AlertManager) DispatchAsync(event *model.SecurityEvent) {
	am.mu.RLock()
	matching := am.matchingWebhooks(event.DetectionResult.Classification)
	am.mu.RUnlock()

	for _, wh := range matching {
		go am.dispatch(wh, event)
	}
}

// matchingWebhooks returns webhooks whose trigger flags match the classification.
// Caller must hold at least a read lock.
func (am *AlertManager) matchingWebhooks(classification string) []model.Webhook {
	var out []model.Webhook
	for _, wh := range am.webhooks {
		switch classification {
		case "safe":
			if wh.TriggerSafe {
				out = append(out, wh)
			}
		case "suspicious":
			if wh.TriggerSuspicious {
				out = append(out, wh)
			}
		case "malicious":
			if wh.TriggerMalicious {
				out = append(out, wh)
			}
		}
	}
	return out
}

// dispatch sends a single webhook HTTP POST and records the result.
func (am *AlertManager) dispatch(wh model.Webhook, event *model.SecurityEvent) {
	payload, _ := json.Marshal(map[string]any{
		"event_id":       event.ID,
		"timestamp":      event.DetectedAt,
		"classification": event.DetectionResult.Classification,
		"risk_score":     event.DetectionResult.RiskScore,
		"command":        event.ExecveEvent.Command,
		"matched_rules":  event.DetectionResult.MatchedRules,
		"explanation":    event.DetectionResult.Explanation,
	})

	resp, err := am.client.Post(wh.URL, "application/json", bytes.NewReader(payload))

	entry := model.AlertHistory{
		ID:             "ah_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:8],
		WebhookID:      wh.ID,
		WebhookURL:     wh.URL,
		EventID:        event.ID,
		Classification: event.DetectionResult.Classification,
		DispatchedAt:   time.Now(),
	}

	if err != nil {
		entry.Success = false
		entry.Error = err.Error()
		slog.Error("alerts: webhook dispatch failed", "url", wh.URL, "err", err)
	} else {
		resp.Body.Close()
		entry.StatusCode = resp.StatusCode
		entry.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
		slog.Debug("alerts: webhook dispatched", "url", wh.URL, "status", resp.StatusCode)
	}

	am.mu.Lock()
	am.history = append(am.history, entry)
	// Keep history bounded.
	if len(am.history) > maxHistory {
		am.history = am.history[len(am.history)-maxHistory:]
	}
	am.mu.Unlock()
}

// ── History ───────────────────────────────────────────────────────────────────

// GetHistory returns a copy of the alert history, newest-first.
func (am *AlertManager) GetHistory() []model.AlertHistory {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if len(am.history) == 0 {
		return []model.AlertHistory{}
	}
	out := make([]model.AlertHistory, len(am.history))
	copy(out, am.history)
	// Reverse: newest-first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
