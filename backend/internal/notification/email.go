// Package notification — Gmail SMTP email report service.
//
// Supports three report formats:
//
//	"html"  — styled HTML table (default)
//	"csv"   — comma-separated values
//	"json"  — raw JSON array
//
// Sends to every department email in the registry (BCC model) plus
// any explicitly supplied recipient list.
package notification

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
	"time"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/config"
	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
)

// EmailService sends formatted security reports via Gmail SMTP.
type EmailService struct {
	cfg *config.Settings
}

// NewEmailService creates an EmailService backed by the supplied config.
func NewEmailService(cfg *config.Settings) *EmailService {
	return &EmailService{cfg: cfg}
}

// IsConfigured returns true when Gmail credentials are present.
func (es *EmailService) IsConfigured() bool {
	return es.cfg.GmailUser != "" && es.cfg.GmailAppPassword != ""
}

// SendReport builds and sends a security report to all department addresses.
//
//   - events  — the SecurityEvents to include
//   - format  — "html" | "csv" | "json"
//   - depts   — list of departments to notify
//   - extra   — optional extra recipient addresses
func (es *EmailService) SendReport(
	events []*model.SecurityEvent,
	format string,
	depts []model.Department,
	extra []string,
) error {
	if !es.IsConfigured() {
		return fmt.Errorf("email: Gmail credentials not configured (set GMAIL_USER and GMAIL_APP_PASSWORD)")
	}

	// Collect recipient list.
	recipients := make([]string, 0, len(depts)+len(extra))
	for _, d := range depts {
		if d.Email != "" {
			recipients = append(recipients, d.Email)
		}
	}
	recipients = append(recipients, extra...)
	if len(recipients) == 0 {
		return fmt.Errorf("email: no recipients — add at least one department or extra address")
	}

	subject := fmt.Sprintf("AEGIX Security Report — %d events (%s)",
		len(events), time.Now().Format("2006-01-02 15:04 MST"))

	body, contentType, err := es.buildBody(events, format)
	if err != nil {
		return fmt.Errorf("email: build body: %w", err)
	}

	from := es.cfg.GmailFromEmail
	if from == "" {
		from = es.cfg.GmailUser
	}

	msg := es.buildMIME(from, recipients, subject, body, contentType)
	addr := fmt.Sprintf("%s:%d", es.cfg.GmailSMTPHost, es.cfg.GmailSMTPPort)
	auth := smtp.PlainAuth("", es.cfg.GmailUser, es.cfg.GmailAppPassword, es.cfg.GmailSMTPHost)

	if err := smtp.SendMail(addr, auth, from, recipients, msg); err != nil {
		slog.Error("email: send failed", "err", err)
		return fmt.Errorf("email: send: %w", err)
	}

	slog.Info("email: report sent",
		"recipients", len(recipients),
		"events", len(events),
		"format", format)
	return nil
}

// ── Body builders ─────────────────────────────────────────────────────────────

func (es *EmailService) buildBody(events []*model.SecurityEvent, format string) ([]byte, string, error) {
	switch strings.ToLower(format) {
	case "csv":
		return es.buildCSV(events)
	case "json":
		return es.buildJSONBody(events)
	default: // "html"
		return es.buildHTML(events)
	}
}

func (es *EmailService) buildHTML(events []*model.SecurityEvent) ([]byte, string, error) {
	var b bytes.Buffer
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AEGIX Security Report</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:24px}
  h1{color:#38bdf8;margin-bottom:4px}
  p{color:#94a3b8;margin:0 0 16px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#1e293b;color:#7dd3fc;padding:10px 12px;text-align:left;border-bottom:2px solid #334155}
  td{padding:9px 12px;border-bottom:1px solid #1e293b;vertical-align:top}
  tr:hover td{background:#1e293b}
  .safe{color:#4ade80}.suspicious{color:#fb923c}.malicious{color:#f87171}
  .cmd{font-family:monospace;font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
</style>
</head>
<body>
<h1>🛡 AEGIX Security Report</h1>
<p>Generated: ` + time.Now().Format("2006-01-02 15:04:05 MST") + ` &nbsp;|&nbsp; Events: ` + fmt.Sprint(len(events)) + `</p>
<table>
<thead>
<tr><th>ID</th><th>Time</th><th>Classification</th><th>Risk</th><th>Command</th><th>Matched Rules</th></tr>
</thead>
<tbody>
`)

	for _, e := range events {
		t := time.Unix(int64(e.DetectedAt), 0).Format("15:04:05")
		cls := e.DetectionResult.Classification
		rules := strings.Join(e.DetectionResult.MatchedRules, ", ")
		if rules == "" {
			rules = "—"
		}
		fmt.Fprintf(&b, `<tr>
<td>%s</td>
<td>%s</td>
<td class="%s">%s</td>
<td>%.1f</td>
<td class="cmd" title="%s">%s</td>
<td>%s</td>
</tr>`,
			e.ID, t, cls, strings.ToUpper(cls[:1])+cls[1:],
			e.DetectionResult.RiskScore,
			e.ExecveEvent.Command, truncate(e.ExecveEvent.Command, 60),
			rules,
		)
	}

	b.WriteString(`</tbody></table></body></html>`)
	return b.Bytes(), "text/html", nil
}

func (es *EmailService) buildCSV(events []*model.SecurityEvent) ([]byte, string, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"id", "detected_at", "classification", "risk_score", "command", "matched_rules"})
	for _, e := range events {
		_ = w.Write([]string{
			e.ID,
			time.Unix(int64(e.DetectedAt), 0).Format(time.RFC3339),
			e.DetectionResult.Classification,
			fmt.Sprintf("%.1f", e.DetectionResult.RiskScore),
			e.ExecveEvent.Command,
			strings.Join(e.DetectionResult.MatchedRules, "; "),
		})
	}
	w.Flush()
	return buf.Bytes(), "text/csv", w.Error()
}

func (es *EmailService) buildJSONBody(events []*model.SecurityEvent) ([]byte, string, error) {
	flat := make([]map[string]any, len(events))
	for i, e := range events {
		flat[i] = e.Flatten()
	}
	data, err := json.MarshalIndent(flat, "", "  ")
	return data, "application/json", err
}

// ── MIME builder ──────────────────────────────────────────────────────────────

func (es *EmailService) buildMIME(from string, to []string, subject string, body []byte, contentType string) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: AEGIX Security <%s>\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&buf, "Subject: %s\r\n", subject)
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: %s; charset=UTF-8\r\n", contentType)
	fmt.Fprintf(&buf, "\r\n")
	buf.Write(body)
	return buf.Bytes()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
