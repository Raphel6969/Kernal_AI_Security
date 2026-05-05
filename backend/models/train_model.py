"""
Machine learning model training for RCE detection.
Trains a Logistic Regression classifier on labeled command data.
"""

import pickle
import os
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import numpy as np


class CommandFeatureExtractor:
    """Extract features from command strings for ML classification."""

    @staticmethod
    def extract_features(command: str) -> dict:
        """
        Extract hand-crafted features from a command.
        
        Args:
            command: Command string
            
        Returns:
            Dictionary of features
        """
        features = {
            'length': len(command),
            'special_char_count': sum(1 for c in command if c in ';|&()$`\\'),
            'pipe_count': command.count('|'),
            'semicolon_count': command.count(';'),
            'ampersand_count': command.count('&'),
            'has_redirect': '>' in command or '<' in command,
            'has_wildcard': '*' in command or '?' in command,
        }
        
        # Tokenize and count suspicious keywords
        tokens = command.lower().split()
        suspicious_keywords = [
            'bash', 'sh', 'eval', 'exec', 'curl', 'wget', 'nc', 'ncat',
            'socat', 'python', 'perl', 'ruby', 'php', 'node'
        ]
        features['suspicious_keyword_count'] = sum(
            1 for token in tokens if any(kw in token for kw in suspicious_keywords)
        )
        
        return features


def load_training_data(safe_file: str, malicious_file: str) -> tuple:
    """
    Load training data from files.
    
    Args:
        safe_file: Path to file with safe commands (one per line)
        malicious_file: Path to file with malicious commands (one per line)
        
    Returns:
        Tuple of (commands, labels) where labels are 0 (safe) and 1 (malicious)
    """
    commands = []
    labels = []
    
    # Load safe commands
    with open(safe_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line:  # Skip empty lines
                commands.append(line)
                labels.append(0)  # Safe = 0
    
    # Load malicious commands
    with open(malicious_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line:  # Skip empty lines
                commands.append(line)
                labels.append(1)  # Malicious = 1
    
    return commands, labels


def train_model(safe_file: str, malicious_file: str, output_path: str) -> dict:
    """
    Train a Logistic Regression model for command classification.
    
    Args:
        safe_file: Path to safe commands file
        malicious_file: Path to malicious commands file
        output_path: Where to save the trained model
        
    Returns:
        Dictionary with model and metrics
    """
    print("📚 Loading training data...")
    commands, labels = load_training_data(safe_file, malicious_file)
    print(f"   Loaded {len(commands)} commands ({sum(labels)} malicious, {len(labels)-sum(labels)} safe)")
    
    # Split data (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        commands, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    print(f"📊 Training set: {len(X_train)} samples")
    print(f"📊 Test set: {len(X_test)} samples")
    
    # Feature extraction using TF-IDF
    print("🔤 Extracting features with TF-IDF...")
    vectorizer = TfidfVectorizer(
        max_features=500,
        ngram_range=(1, 2),
        min_df=1,
        max_df=0.95,
    )
    
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    # Train Logistic Regression
    print("🤖 Training Logistic Regression model...")
    model = LogisticRegression(
        max_iter=1000,
        solver='lbfgs',
        random_state=42,
        class_weight='balanced',  # Handle class imbalance
    )
    
    model.fit(X_train_tfidf, y_train)
    
    # Evaluate
    print("\n📈 Model Evaluation:")
    y_pred = model.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"   Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\n   Classification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=['Safe', 'Malicious'],
        digits=4
    ))
    
    print("\n   Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"   TN={cm[0,0]}, FP={cm[0,1]}")
    print(f"   FN={cm[1,0]}, TP={cm[1,1]}")
    
    # Save model and vectorizer
    print(f"\n💾 Saving model to {output_path}...")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    model_data = {
        'model': model,
        'vectorizer': vectorizer,
        'accuracy': accuracy,
    }
    
    with open(output_path, 'wb') as f:
        pickle.dump(model_data, f)
    
    print("✅ Model saved successfully!")
    
    return model_data


if __name__ == '__main__':
    # Setup paths
    project_root = Path(__file__).parent.parent.parent
    safe_file = project_root / 'data' / 'commands_safe.txt'
    malicious_file = project_root / 'data' / 'commands_malicious.txt'
    output_path = project_root / 'backend' / 'models' / 'trained_model.pkl'
    
    # Train
    train_model(str(safe_file), str(malicious_file), str(output_path))
