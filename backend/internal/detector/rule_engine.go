// Package detector — Rule-based threat scoring engine.
//
// Mirrors the Python RuleEngine exactly:
//   - Regex pattern matching   (40 pts each, capped at 100)
//   - Keyword scoring          (fixed weights per keyword)
//   - Shannon entropy penalty  (obfuscation detection)
//   - Memory spike anomaly     (high initial process allocation)
package detector

import (
	"math"
	"regexp"
	"strings"
	"sync"
)

// rulePattern is a compiled pattern with its name and score contribution.
type rulePattern struct {
	name string
	re   *regexp.Regexp
}

// RuleEngine performs deterministic, rule-based threat scoring.
// All regex patterns are compiled once at construction and reused
// concurrently — the engine is safe for concurrent use.
type RuleEngine struct {
	patterns []rulePattern
	keywords map[string]float64
}

// ruleEngineOnce protects the package-level singleton.
var (
	ruleEngineOnce     sync.Once
	ruleEngineSingleton *RuleEngine
)

// GetRuleEngine returns the package-level RuleEngine singleton.
func GetRuleEngine() *RuleEngine {
	ruleEngineOnce.Do(func() {
		ruleEngineSingleton = newRuleEngine()
	})
	return ruleEngineSingleton
}

// newRuleEngine constructs and compiles all detection patterns.
func newRuleEngine() *RuleEngine {
	// rawPatterns maps rule-name → list of regex strings.
	// All patterns are matched case-insensitively.
	rawPatterns := map[string][]string{
		"reverse_shell": {
			`/dev/tcp/`,
			`bash\s*-i`,
			`nc\s+-e\s*/bin`,
			`ncat\s+.*-e`,
		},
		"pipe_to_shell": {
			`\|\s*bash`,
			`\|\s*sh\b`,
			`\|\s*zsh`,
		},
		"obfuscated_b64": {
			`base64\s+-d`,
			`base64\s+--decode`,
			`\{echo,`,
		},
		"destructive": {
			`rm\s+-rf\s+/\s+--no-preserve`,
			`dd\s+if=/dev/zero`,
			`mkfs\.`,
		},
		"priv_esc": {
			`chmod\s+4[0-9]{3}\s+/bin/`,
			`NOPASSWD:ALL`,
		},
		"data_exfil": {
			`cat\s+/etc/shadow`,
			`find.*id_rsa.*xargs\s+cat`,
			`\|\s*nc\s+\d+\.\d+\.\d+\.\d+`,
		},
		"fork_bomb": {
			`:\(\)\s*\{`,
			`:\|:\&`,
		},
		"log_wipe": {
			`shred.*\s+/var/log`,
			`truncate\s+-s\s+0\s+/var/log/`,
		},
		"download_exec": {
			`wget.*-O\s+/tmp.*&&.*chmod.*&&`,
			`curl.*\|\s*bash`,
		},
		"ssh_inject": {
			`authorized_keys`,
		},
		"web_shell": {
			`php.*system\(\$`,
			`php.*passthru\(\$`,
		},
		"eval_payload": {
			`eval\s*\$\(\s*cat`,
			`exec\s*\$\(\s*cat`,
		},
		"kernel_module": {
			`insmod\s+`,
			`modprobe\s+`,
		},
		"crontab_inject": {
			`crontab\s+-`,
			`/etc/cron`,
		},
		"lolbin_exec": {
			`perl\s+-e\s+['"].*exec`,
			`python.*-c.*exec`,
			`ruby\s+-e\s+.*exec`,
		},
	}

	// Compile all patterns, prefixing (?i) for case-insensitive matching.
	var patterns []rulePattern
	for name, regexList := range rawPatterns {
		for _, raw := range regexList {
			compiled, err := regexp.Compile(`(?i)` + raw)
			if err != nil {
				// Should never happen with well-formed literals — panic loudly.
				panic("detector: invalid rule pattern " + raw + ": " + err.Error())
			}
			patterns = append(patterns, rulePattern{name: name, re: compiled})
		}
	}

	return &RuleEngine{
		patterns: patterns,
		keywords: map[string]float64{
			"eval":           25,
			"exec":           20,
			"base64":         30,
			"nc ":            25,
			"/tmp/":          10,
			"pty.spawn":      30,
			"socket.connect": 25,
			"os.dup2":        25,
		},
	}
}

// Score evaluates a command against all rules and returns
// (totalScore 0-100, matchedRuleNames).
//
// Parameters:
//   - command       — the raw command string to evaluate
//   - processMem    — process memory usage in MB at T=0 (0 if unknown)
//   - systemMemPct  — system-wide RAM usage percentage  (0 if unknown)
func (r *RuleEngine) Score(command string, processMem, systemMemPct float64) (float64, []string) {
	score := 0.0
	seen := make(map[string]bool)   // dedup rule names
	var matched []string

	cmdLower := strings.ToLower(command)

	// ── 1. Regex pattern matching (40 pts per distinct rule hit) ─────────────
	for _, p := range r.patterns {
		if seen[p.name] {
			continue // already scored this rule category
		}
		if p.re.MatchString(command) {
			score += 40
			seen[p.name] = true
			matched = append(matched, p.name)
		}
	}

	// ── 2. Keyword scoring ────────────────────────────────────────────────────
	for kw, pts := range r.keywords {
		if strings.Contains(cmdLower, kw) {
			score += pts
			label := "keyword_" + strings.NewReplacer(" ", "_", "/", "_").Replace(strings.TrimSpace(kw))
			matched = append(matched, label)
		}
	}

	// ── 3. Shannon entropy (obfuscation detection) ────────────────────────────
	entropy := shannonEntropy(command)
	switch {
	case entropy > 4.5:
		score += 20
		matched = append(matched, "high_entropy_obfuscation")
	case entropy > 3.8:
		score += 10
		matched = append(matched, "moderate_entropy")
	}

	// ── 4. Memory anomaly (process allocated >50 MB at exec time) ────────────
	if processMem > 50.0 {
		score += 30
		matched = append(matched, "memory_hog")
	}
	if systemMemPct > 80.0 {
		score += 10
		matched = append(matched, "system_memory_critical")
	}

	if score > 100 {
		score = 100
	}
	return score, dedup(matched)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// shannonEntropy computes the Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// dedup removes duplicate strings while preserving order.
func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
