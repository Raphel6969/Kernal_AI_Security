"""
Rule-based detection engine for RCE prevention.
Detects common attack patterns through keyword and regex matching.
"""

import re
from typing import List, Tuple

class RuleEngine:
    """
    Rule-based detection for malicious commands.
    Uses keyword matching and regex patterns to identify RCE attack vectors.
    """

    def __init__(self):
        # Command injection operators
        self.injection_operators = [';', '&&', '||', '|', '\n', '\r', '&']
        
        # Shell execution tools
        self.shell_tools = ['bash', 'sh', 'zsh', 'ksh', 'csh', 'dash', 'eval', 'exec', 'source']
        
        # Reverse shell patterns
        self.reverse_shell_patterns = [
            '/dev/tcp/',
            '/dev/udp/',
            'nc -',
            'ncat',
            'socat',
            'tclsh',
        ]
        
        # Suspicious tools for downloads/execution
        self.suspicious_tools = [
            'curl',
            'wget',
            'python',
            'python3',
            'perl',
            'ruby',
            'php',
            'node',
            'awk',
            'sed',
            'paste',
        ]
        
        # Destructive commands
        self.destructive_patterns = [
            r'rm\s+-rf\s+/',
            r'mkfs\.',
            r'dd\s+if=/dev/(zero|random|mem)',
            r':\(\)',  # Bash fork bomb
        ]
        
        # Privilege escalation patterns
        self.privesc_patterns = [
            r'sudo\s+-u\s+root',
            r'su\s+-',
            r'su\s+root',
            r'chmod\s+777\s+/etc/(shadow|passwd)',
        ]
        
        # File/data exfiltration
        self.exfiltration_patterns = [
            r'cat\s+/etc/(shadow|passwd)',
            r'/root/\.ssh',
            r'/etc/(shadow|passwd)\s*>',
            r'dd\s+if=/dev/(sda|mem|zero)',
        ]
        
        # Encoded payload detection
        self.encoding_patterns = [
            r'base64\s+(-d|--decode)',
            r'echo.*\|.*base64',
            r'xxd\s+-r',
            r'printf\s+.*\\x',
            r'od\s+.*-t',
        ]

    def score_rules(self, command: str) -> Tuple[float, List[str]]:
        """
        Score a command based on rule matches.
        
        Args:
            command: The command string to analyze
            
        Returns:
            Tuple of (risk_score: 0-100, matched_rules: list of rule names)
        """
        risk_score = 0.0
        matched_rules = []
        
        # Check for injection operators combined with suspicious tools
        if self._has_piping_to_shell(command):
            risk_score += 45
            matched_rules.append("shell_piping")
        
        # Check for reverse shell patterns
        if self._has_reverse_shell_pattern(command):
            risk_score += 55
            matched_rules.append("reverse_shell_pattern")
        
        # Check for destructive patterns
        if self._has_destructive_pattern(command):
            risk_score += 65
            matched_rules.append("destructive_pattern")
        
        # Check for privilege escalation
        if self._has_privesc_pattern(command):
            risk_score += 45
            matched_rules.append("privilege_escalation")
        
        # Check for data exfiltration
        if self._has_exfiltration_pattern(command):
            risk_score += 40
            matched_rules.append("data_exfiltration")
        
        # Check for encoded payloads
        if self._has_encoding_pattern(command):
            risk_score += 25
            matched_rules.append("encoded_payload")
        
        # Cap at 100
        return min(risk_score, 100), matched_rules

    def _has_piping_to_shell(self, command: str) -> bool:
        """Detect piping to shell: curl | bash, etc."""
        for tool in self.suspicious_tools:
            for op in ['|', '||', '&&']:
                for shell in self.shell_tools:
                    pattern = f'{tool}.*{re.escape(op)}\\s*{shell}'
                    if re.search(pattern, command, re.IGNORECASE):
                        return True
        return False

    def _has_reverse_shell_pattern(self, command: str) -> bool:
        """Detect reverse shell patterns."""
        for pattern in self.reverse_shell_patterns:
            if pattern in command:
                return True
        return False

    def _has_destructive_pattern(self, command: str) -> bool:
        """Detect destructive/wiping patterns."""
        for pattern in self.destructive_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False

    def _has_privesc_pattern(self, command: str) -> bool:
        """Detect privilege escalation attempts."""
        for pattern in self.privesc_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False

    def _has_exfiltration_pattern(self, command: str) -> bool:
        """Detect data exfiltration patterns."""
        for pattern in self.exfiltration_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False

    def _has_encoding_pattern(self, command: str) -> bool:
        """Detect encoded/obfuscated payloads."""
        for pattern in self.encoding_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False


# Singleton instance
_rule_engine = None

def get_rule_engine() -> RuleEngine:
    """Get or create the rule engine singleton."""
    global _rule_engine
    if _rule_engine is None:
        _rule_engine = RuleEngine()
    return _rule_engine
