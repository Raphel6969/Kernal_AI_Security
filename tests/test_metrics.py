import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_squared_error, average_precision_score
import pickle

def test_extra_metrics():
    project_root = Path(__file__).parent
    # Prefer test-local data, but fall back to repository-level `data/` and `backend/models/`.
    safe_file = project_root / 'data' / 'safe_commands_10k.txt'
    malicious_file = project_root / 'data' / 'malicious_commands_2k.txt'
    model_path = project_root / 'backend' / 'models' / 'trained_model.pkl'
    if not safe_file.exists():
        repo_root = project_root.parent
        safe_file = repo_root / 'data' / 'safe_commands_10k.txt'
    if not malicious_file.exists():
        repo_root = project_root.parent
        malicious_file = repo_root / 'data' / 'malicious_commands_2k.txt'
    if not model_path.exists():
        repo_root = project_root.parent
        model_path = repo_root / 'backend' / 'models' / 'trained_model.pkl'

    # Load data
    with open(safe_file, 'r', encoding='utf-8') as f:
        safe_cmds = [line.strip() for line in f if line.strip()]
    with open(malicious_file, 'r', encoding='utf-8') as f:
        mal_cmds = [line.strip() for line in f if line.strip()]

    commands = safe_cmds + mal_cmds
    # numeric labels: 0 for safe, 1 for malicious
    labels = [0]*len(safe_cmds) + [1]*len(mal_cmds)

    # exact same split
    X_train, X_test, y_train, y_test = train_test_split(
        commands, labels, test_size=0.2, random_state=42, stratify=labels
    )

    # load model
    with open(model_path, 'rb') as f:
        model_data = pickle.load(f)
    
    model = model_data['model']
    vectorizer = model_data['vectorizer']

    # Vectorize and predict probabilities
    X_test_tfidf = vectorizer.transform(X_test)
    
    # predict_proba returns probabilities for [safe, malicious]. 
    print(f"Model classes: {model.classes_}")
    if "malicious" in model.classes_:
        class_idx = list(model.classes_).index("malicious")
    elif 1 in model.classes_:
        class_idx = list(model.classes_).index(1)
    else:
        class_idx = 1 # fallback
        
    y_prob = model.predict_proba(X_test_tfidf)[:, class_idx]

    # Calculate metrics
    r2 = r2_score(y_test, y_prob)
    rmse = np.sqrt(mean_squared_error(y_test, y_prob))
    map_score = average_precision_score(y_test, y_prob)

    print("\n📊 Advanced Model Metrics:")
    print(f"R² Score: {r2:.4f}")
    print(f"RMSE (Root Mean Square Error): {rmse:.4f}")
    print(f"MAP (Mean Average Precision): {map_score:.4f}")

if __name__ == '__main__':
    test_extra_metrics()
