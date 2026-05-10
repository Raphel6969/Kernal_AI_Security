"""
Rule-based detection engine for RCE prevention.
Detects common attack patterns through keyword, regex matching, and entropy.
"""

import re
import math
from collections import defaultdict
from typing import List, Tuple

class RuleEngine:
    """
    Rule-based detection for malicious commands.
    Uses pattern matching, keyword scoring, and Shannon entropy.
    """

    def __init__(self):
        self.patterns = {
            "reverse_shell":  [
                r"/dev/tcp/",
                r"bash\s*-i",
                r"nc\s+-e\s*/bin",
                r"ncat\s+.*-e",
            ],
            "pipe_to_shell":  [r"\|\s*bash", r"\|\s*sh\b", r"\|\s*zsh"],
            "obfuscated_b64": [r"base64\s+-d", r"base64\s+--decode", r"\{echo,"],
            "destructive":    [
                r"rm\s+-rf\s+/\s+--no-preserve",
                r"dd\s+if=/dev/zero",
                r"mkfs\.",
            ],
            "priv_esc":       [r"chmod\s+4[0-9]{3}\s+/bin/", r"NOPASSWD:ALL"],
            "data_exfil":     [
                r"cat\s+/etc/shadow",
                r"find.*id_rsa.*xargs\s+cat",
                r"\|\s*nc\s+\d+\.\d+\.\d+\.\d+",
            ],
            "fork_bomb":      [r":\(\)\s*\{", r":\|\:&"],
            "log_wipe":       [r"shred.*\s+/var/log", r"truncate\s+-s\s+0\s+/var/log/"],
            "download_exec":  [r"wget.*-O\s+/tmp.*&&.*chmod.*&&", r"curl.*\|\s*bash"],
            "ssh_inject":     [r"authorized_keys"],
            "web_shell":      [r"php.*system\(\$", r"php.*passthru\(\$"],
            "eval_payload":   [r"eval\s*\$\(\s*cat", r"exec\s*\$\(\s*cat"],
        }

        self.keyword_scores = {
            "eval": 25, "exec": 20, "base64": 30, "nc ": 25,
            "/tmp/": 10,  "pty.spawn": 30, "socket.connect": 25, "os.dup2": 25,
        }

    def _shannon_entropy(self, s: str) -> float:
        """Compute Shannon entropy of a string."""
        if not s:
            return 0.0
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())

    def score_rules(self, command: str) -> Tuple[float, List[str]]:
        """
        Score a command based on rule matches, keywords, and entropy.
        
        Args:
            command: The command string to analyze
            
        Returns:
            Tuple of (risk_score: 0-100, matched_rules: list of rule names)
        """
        score = 0.0
        matched_rules = []
        cmd_lower = command.lower()

        # Check Patterns
        for rule_name, patterns in self.patterns.items():
            for pat in patterns:
                if re.search(pat, command, re.IGNORECASE):
                    score += 40
                    matched_rules.append(rule_name)
                    break

        # Check Keywords
        for kw, pts in self.keyword_scores.items():
            if kw in cmd_lower:
                score += pts

        # Add Entropy Penalty for obfuscation
        ent = self._shannon_entropy(command)
        if ent > 4.5:
            score += 20
            matched_rules.append("high_entropy_obfuscation")
        elif ent > 3.8:
            score += 10
            matched_rules.append("moderate_entropy")

        return min(score, 100.0), list(set(matched_rules))


# Singleton instance
_rule_engine = None

def get_rule_engine() -> RuleEngine:
    """Get or create the rule engine singleton."""
    global _rule_engine
    if _rule_engine is None:
        _rule_engine = RuleEngine()
    return _rule_engine
