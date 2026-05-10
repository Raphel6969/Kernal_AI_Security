"""
Main detection pipeline combining rule-based and ML scoring.
Orchestrates the full detection workflow.
"""

from typing import Optional
from backend.detection.rule_engine import get_rule_engine
from backend.detection.ml_scorer import get_ml_scorer
from backend.events.models import DetectionResult


class DetectionPipeline:
    """
    Combined detection pipeline using rules (60%) and ML (40%).
    """

    def __init__(self, rule_weight: float = 0.6, ml_weight: float = 0.4):
        """
        Initialize detection pipeline.
        
        Args:
            rule_weight: Weight for rule-based score (default 60%)
            ml_weight: Weight for ML score (default 40%)
        """
        if abs((rule_weight + ml_weight) - 1.0) > 0.001:
            raise ValueError(f"Weights must sum to 1.0, got {rule_weight + ml_weight}")
        
        self.rule_weight = rule_weight
        self.ml_weight = ml_weight
        self.rule_engine = get_rule_engine()
        self.ml_scorer = None
        
        # Try to load ML scorer, but don't fail if model not available yet
        try:
            self.ml_scorer = get_ml_scorer()
        except FileNotFoundError:
            print("⚠️  ML model not yet trained. Detection will use rules only.")
            
        self.suspicious_threshold = 25.0
        self.malicious_threshold = 60.0

    def update_thresholds(self, suspicious: float, malicious: float):
        self.suspicious_threshold = suspicious
        self.malicious_threshold = malicious

    def detect(self, command: str, process_memory_mb: float = 0.0, system_memory_percent: float = 0.0) -> DetectionResult:
        """
        Analyze a command and return detection result.
        
        Args:
            command: Command string to analyze
            process_memory_mb: Instantaneous memory allocation
            system_memory_percent: Total system RAM usage
            
        Returns:
            DetectionResult with risk score and classification
        """
        # Get rule-based score
        rule_score, matched_rules = self.rule_engine.score_rules(
            command, 
            process_memory_mb=process_memory_mb, 
            system_memory_percent=system_memory_percent
        )
        
        # Get ML score
        ml_score = 0.0
        ml_confidence = 0.0
        if self.ml_scorer:
            ml_score, ml_confidence = self.ml_scorer.score_ml(command)
        
        # Combine scores (weighted average)
        if self.ml_scorer:
            combined_score = (self.rule_weight * rule_score) + (self.ml_weight * ml_score)
        else:
            # If ML not available, use rules only
            combined_score = rule_score
        
        # Classify based on score
        if combined_score < self.suspicious_threshold:
            classification = "safe"
        elif combined_score < self.malicious_threshold:
            classification = "suspicious"
        else:
            classification = "malicious"
        
        # Build explanation
        explanation = self._build_explanation(
            classification, combined_score, matched_rules, ml_confidence
        )
        
        return DetectionResult(
            risk_score=combined_score,
            classification=classification,
            matched_rules=matched_rules,
            ml_confidence=ml_confidence,
            explanation=explanation,
        )

    def _build_explanation(
        self,
        classification: str,
        risk_score: float,
        matched_rules: list,
        ml_confidence: float,
    ) -> str:
        """
        Build a human-readable explanation of the detection.
        
        Args:
            classification: The classification result
            risk_score: The risk score (0-100)
            matched_rules: List of triggered rules
            ml_confidence: ML model confidence
            
        Returns:
            Explanation string
        """
        parts = []
        
        # Classification explanation
        if classification == "safe":
            parts.append("✅ Command appears safe.")
        elif classification == "suspicious":
            parts.append("⚠️  Command is suspicious and may pose a risk.")
        else:  # malicious
            parts.append("🚨 Command is likely malicious and should be blocked.")
        
        parts.append(f"Risk Score: {risk_score:.1f}/100")
        
        # Matched rules
        if matched_rules:
            parts.append(f"Detected patterns: {', '.join(matched_rules)}")
        else:
            parts.append("No suspicious patterns detected in command.")
        
        # ML confidence
        if self.ml_scorer:
            parts.append(f"ML Model confidence: {ml_confidence*100:.1f}%")
        
        return " | ".join(parts)


# Singleton instance
_detection_pipeline = None


def get_detection_pipeline(
    rule_weight: float = 0.6, ml_weight: float = 0.4
) -> DetectionPipeline:
    """
    Get or create the detection pipeline singleton.
    
    Args:
        rule_weight: Weight for rule-based score
        ml_weight: Weight for ML score
        
    Returns:
        The global DetectionPipeline instance
    """
    global _detection_pipeline
    if _detection_pipeline is None:
        _detection_pipeline = DetectionPipeline(rule_weight, ml_weight)
    return _detection_pipeline
