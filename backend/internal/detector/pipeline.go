// Package detector — Detection pipeline combining Rule Engine (60%) + ML (40%).
//
// Matches Python DetectionPipeline exactly:
//   - Combined score = 0.6 × rule_score + 0.4 × ml_score
//   - If ML is unavailable, combined score = rule_score (100% rules)
//   - Thresholds: suspicious ≥ 25, malicious ≥ 60
//   - Returns a *model.DetectionResult for each analysed command
package detector

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/Raphel6969/Kernal_AI_Security/backend/internal/model"
)

// Pipeline is the combined threat-detection pipeline.
// It is safe for concurrent use.
type Pipeline struct {
	rules      *RuleEngine
	ml         *MLScorer
	ruleWeight float64
	mlWeight   float64

	mu                  sync.RWMutex // protects the two threshold fields
	SuspiciousThreshold float64
	MaliciousThreshold  float64
}

var (
	pipelineOnce      sync.Once
	pipelineSingleton *Pipeline
)

// GetPipeline returns (or initialises) the package-level Pipeline singleton.
// modelPath points to data/trained_model.json; pass "" to disable ML scoring.
func GetPipeline(modelPath string) *Pipeline {
	pipelineOnce.Do(func() {
		pipelineSingleton = newPipeline(modelPath)
	})
	return pipelineSingleton
}

func newPipeline(modelPath string) *Pipeline {
	p := &Pipeline{
		rules:               GetRuleEngine(),
		ruleWeight:          0.6,
		mlWeight:            0.4,
		SuspiciousThreshold: 25.0,
		MaliciousThreshold:  60.0,
	}

	if modelPath != "" {
		p.ml = GetMLScorer(modelPath)
		if !p.ml.IsReady() {
			slog.Warn("Pipeline: ML scorer unavailable — rules-only mode")
		}
	} else {
		slog.Info("Pipeline: no model path provided — rules-only mode")
	}

	return p
}

// UpdateThresholds adjusts the classification thresholds at runtime.
// Thread-safe.
func (p *Pipeline) UpdateThresholds(suspicious, malicious float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.SuspiciousThreshold = suspicious
	p.MaliciousThreshold = malicious
	slog.Info("Pipeline: thresholds updated",
		"suspicious", suspicious, "malicious", malicious)
}

// GetThresholds returns the current thresholds.
func (p *Pipeline) GetThresholds() (suspicious, malicious float64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.SuspiciousThreshold, p.MaliciousThreshold
}

// Detect analyses a command and returns a fully populated DetectionResult.
//
// Parameters:
//   - command     — the raw command string to analyse
//   - processMem  — instantaneous process RSS in MB (0 if unavailable)
//   - systemMem   — system-wide RAM usage percentage  (0 if unavailable)
func (p *Pipeline) Detect(command string, processMem, systemMem float64) *model.DetectionResult {
	// ── Tier A: Rule Engine ───────────────────────────────────────────────────
	ruleScore, matchedRules := p.rules.Score(command, processMem, systemMem)

	// ── Tier B: ML Scorer ─────────────────────────────────────────────────────
	var mlScore, mlConfidence float64
	mlReady := p.ml != nil && p.ml.IsReady()
	if mlReady {
		mlScore, mlConfidence = p.ml.Score(command)
	}

	// ── Weighted combination ──────────────────────────────────────────────────
	var combined float64
	if mlReady {
		combined = p.ruleWeight*ruleScore + p.mlWeight*mlScore
	} else {
		combined = ruleScore // rules-only fallback
	}
	if combined > 100 {
		combined = 100
	}

	// ── Classification ────────────────────────────────────────────────────────
	p.mu.RLock()
	suspT := p.SuspiciousThreshold
	malT := p.MaliciousThreshold
	p.mu.RUnlock()

	var classification string
	switch {
	case combined >= malT:
		classification = "malicious"
	case combined >= suspT:
		classification = "suspicious"
	default:
		classification = "safe"
	}

	// ── Explanation ───────────────────────────────────────────────────────────
	explanation := buildExplanation(classification, combined, matchedRules, mlConfidence, mlReady)

	return &model.DetectionResult{
		RiskScore:      combined,
		Classification: classification,
		MatchedRules:   matchedRules,
		MLConfidence:   mlConfidence,
		Explanation:    explanation,
	}
}

// ── Explanation builder ───────────────────────────────────────────────────────

// buildExplanation produces a human-readable detection summary.
// Output format is identical to the Python _build_explanation method so the
// React frontend displays the same strings.
func buildExplanation(
	classification string,
	riskScore float64,
	matchedRules []string,
	mlConfidence float64,
	mlReady bool,
) string {
	var parts []string

	switch classification {
	case "safe":
		parts = append(parts, "✅ Command appears safe.")
	case "suspicious":
		parts = append(parts, "⚠️  Command is suspicious and may pose a risk.")
	default: // malicious
		parts = append(parts, "🚨 Command is likely malicious and should be blocked.")
	}

	parts = append(parts, fmt.Sprintf("Risk Score: %.1f/100", riskScore))

	if len(matchedRules) > 0 {
		parts = append(parts, "Detected patterns: "+strings.Join(matchedRules, ", "))
	} else {
		parts = append(parts, "No suspicious patterns detected in command.")
	}

	if mlReady {
		parts = append(parts, fmt.Sprintf("ML Model confidence: %.1f%%", mlConfidence*100))
	}

	return strings.Join(parts, " | ")
}
