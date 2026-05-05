"""
ML-based scoring for command classification.
Loads trained model and provides inference for threat assessment.
"""

import pickle
from pathlib import Path
from typing import Tuple


class MLScorer:
    """
    Machine learning based command threat scorer.
    Uses trained Logistic Regression model to classify commands.
    """

    def __init__(self, model_path: str):
        """
        Initialize ML scorer by loading trained model.
        
        Args:
            model_path: Path to trained_model.pkl
        """
        self.model_path = model_path
        self.model = None
        self.vectorizer = None
        self._load_model()

    def _load_model(self) -> None:
        """Load the trained model from disk."""
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.model = model_data['model']
                self.vectorizer = model_data['vectorizer']
                print(f"✅ ML Model loaded: {self.model_path}")
        except FileNotFoundError:
            print(f"⚠️  Model not found at {self.model_path}")
            print("   Run: python backend/models/train_model.py")
            raise
        except Exception as e:
            print(f"❌ Failed to load model: {e}")
            raise

    def score_ml(self, command: str) -> Tuple[float, float]:
        """
        Score a command using the ML model.
        
        Args:
            command: Command string to classify
            
        Returns:
            Tuple of (risk_score: 0-100, confidence: 0-1)
            - risk_score: probability of malicious × 100
            - confidence: max probability from model
        """
        if self.model is None or self.vectorizer is None:
            return 0.0, 0.0
        
        # Vectorize command
        command_tfidf = self.vectorizer.transform([command])
        
        # Get probability predictions
        proba = self.model.predict_proba(command_tfidf)[0]
        
        # proba[0] = probability of safe (label 0)
        # proba[1] = probability of malicious (label 1)
        malicious_prob = proba[1]
        
        risk_score = malicious_prob * 100  # Convert to 0-100 scale
        confidence = max(proba)  # Highest probability among classes
        
        return risk_score, confidence


# Singleton instance
_ml_scorer = None


def get_ml_scorer(model_path: str = None) -> MLScorer:
    """
    Get or create the ML scorer singleton.
    
    Args:
        model_path: Path to trained model (only used on first call)
        
    Returns:
        The global MLScorer instance
    """
    global _ml_scorer
    
    if _ml_scorer is None:
        if model_path is None:
            # Default path should match backend/models/train_model.py output
            project_root = Path(__file__).resolve().parents[2]
            model_path = str(project_root / 'backend' / 'models' / 'trained_model.pkl')
        _ml_scorer = MLScorer(model_path)
    
    return _ml_scorer
