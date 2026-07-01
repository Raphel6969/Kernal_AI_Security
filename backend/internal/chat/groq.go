// Package chat — Groq client for both command explanation AND conversational chat.
//
// Uses Groq's OpenAI-compatible REST API.
// Explanation responses are cached by sha256(command|classification).
// Chat is stateless on the server — the caller passes full history each time.
package chat

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	groqEndpoint  = "https://api.groq.com/openai/v1/chat/completions"
	groqMaxTokens = 600
)

// ChatMessage is one turn in a conversation.
type ChatMessage struct {
	Role    string `json:"role"`    // "user" | "assistant"
	Content string `json:"content"`
}

// GroqClient handles both LLM explanation and conversational chat via Groq.
type GroqClient struct {
	apiKey  string
	model   string
	timeout time.Duration
	cache   sync.Map // cacheKey → string explanation
	client  *http.Client
}

// NewGroqClient constructs a GroqClient.
// If apiKey is empty, every call returns a graceful fallback — no panics.
func NewGroqClient(apiKey, model string, timeoutSec int) *GroqClient {
	if model == "" {
		model = "llama-3.3-70b-versatile"
	}
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &GroqClient{
		apiKey:  apiKey,
		model:   model,
		timeout: time.Duration(timeoutSec) * time.Second,
		client:  &http.Client{Timeout: time.Duration(timeoutSec) * time.Second},
	}
}

// IsConfigured reports whether a Groq API key is set.
func (g *GroqClient) IsConfigured() bool { return g.apiKey != "" }

// ── Explanation ───────────────────────────────────────────────────────────────

// Explain generates a natural-language explanation of why a command was
// classified as it is.  Results are cached; identical command+class pairs
// never hit the network twice in the same process lifetime.
func (g *GroqClient) Explain(
	command, classification string,
	riskScore float64,
	matchedRules []string,
) (string, error) {
	if !g.IsConfigured() {
		return fallbackExplanation(command, classification, riskScore, matchedRules), nil
	}

	key := cacheKey(command, classification)
	if cached, ok := g.cache.Load(key); ok {
		return cached.(string), nil
	}

	prompt := buildExplainPrompt(command, classification, riskScore, matchedRules)
	explanation, err := g.callAPI(groqSecuritySystemPrompt, []ChatMessage{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		slog.Warn("groq: explain failed, using fallback", "err", err)
		return fallbackExplanation(command, classification, riskScore, matchedRules), nil
	}

	g.cache.Store(key, explanation)
	return explanation, nil
}

// ── Chat ──────────────────────────────────────────────────────────────────────

// Chat sends a conversational message with full history to Groq and returns
// the assistant's reply.  history should be ordered [oldest … newest],
// not including the current message.
func (g *GroqClient) Chat(message string, history []ChatMessage) (string, error) {
	if !g.IsConfigured() {
		return "AI chat unavailable: GROQ_API_KEY not configured.", nil
	}

	// Build full message list: history + current user message.
	messages := make([]ChatMessage, 0, len(history)+1)
	messages = append(messages, history...)
	messages = append(messages, ChatMessage{Role: "user", Content: message})

	response, err := g.callAPI(groqChatSystemPrompt, messages)
	if err != nil {
		slog.Warn("groq: chat failed", "err", err)
		return "I'm unable to connect to the AI service right now. Please try again shortly.", nil
	}
	return response, nil
}

// ── Internal ──────────────────────────────────────────────────────────────────

// callAPI sends a chat/completions request and returns the first choice content.
func (g *GroqClient) callAPI(systemPrompt string, messages []ChatMessage) (string, error) {
	// Build the full messages array: system prompt first, then conversation.
	type apiMsg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	apiMessages := make([]apiMsg, 0, len(messages)+1)
	apiMessages = append(apiMessages, apiMsg{Role: "system", Content: systemPrompt})
	for _, m := range messages {
		apiMessages = append(apiMessages, apiMsg{Role: m.Role, Content: m.Content})
	}

	body, _ := json.Marshal(map[string]any{
		"model":       g.model,
		"messages":    apiMessages,
		"max_tokens":  groqMaxTokens,
		"temperature": 0.3,
	})

	req, err := http.NewRequest(http.MethodPost, groqEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.apiKey)

	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("groq: http: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("groq: status %d: %s", resp.StatusCode, string(raw))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Choices) == 0 {
		return "", fmt.Errorf("groq: unexpected response: %s", string(raw))
	}

	return strings.TrimSpace(result.Choices[0].Message.Content), nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func cacheKey(command, classification string) string {
	h := sha256.Sum256([]byte(command + "|" + classification))
	return hex.EncodeToString(h[:16])
}

func buildExplainPrompt(command, classification string, riskScore float64, rules []string) string {
	rulesStr := "none"
	if len(rules) > 0 {
		rulesStr = strings.Join(rules, ", ")
	}
	return fmt.Sprintf(
		"Analyze this Linux command for security threats:\n"+
			"Command: %s\n"+
			"Classification: %s\n"+
			"Risk Score: %.1f/100\n"+
			"Detected Patterns: %s\n\n"+
			"Provide a concise 2-3 sentence explanation of the security risk and "+
			"why this command is classified as %s. Be technical and direct.",
		command, classification, riskScore, rulesStr, classification,
	)
}

func fallbackExplanation(command, classification string, riskScore float64, rules []string) string {
	if len(rules) == 0 {
		return fmt.Sprintf(
			"Command classified as %s with risk score %.1f/100 based on ML model analysis.",
			classification, riskScore,
		)
	}
	return fmt.Sprintf(
		"Command classified as %s (risk %.1f/100). Detected patterns: %s.",
		classification, riskScore, strings.Join(rules, ", "),
	)
}

// ── System prompts ────────────────────────────────────────────────────────────

const groqSecuritySystemPrompt = `You are AEGIX, an advanced cybersecurity AI specializing in Linux command security analysis.
You help security teams understand threats: reverse shells, privilege escalation, data exfiltration,
fork bombs, obfuscation techniques, and other malicious patterns.
Keep responses concise, technical, and actionable. Only explain what is evident from the command.`

const groqChatSystemPrompt = `You are AEGIX, an intelligent cybersecurity assistant embedded in a real-time Linux command monitoring system.
You help security engineers analyze detected commands, understand threat patterns, plan responses, and improve security posture.

Your expertise:
- Reverse shell detection and analysis
- Privilege escalation (SUID, sudo abuse, kernel exploits)
- Data exfiltration (netcat, curl, DNS tunneling)
- Obfuscation and evasion (base64, hex encoding, LOLBins)
- Malware behaviour patterns
- Incident response playbooks
- Linux security hardening

Guidelines:
- Be concise, technical, and actionable
- Use markdown formatting for readability
- Reference specific command components when analysing
- Never suggest or generate malicious code
- If asked something outside security, politely redirect`
