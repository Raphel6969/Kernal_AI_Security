"""
Dataset Cleansing Script
Evaluates all commands in the safe dataset using the RuleEngine.
Any command scoring >= 25.0 (Suspicious threshold) is removed from the safe
dataset and appended to the malicious dataset.
"""

import os
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from backend.detection.rule_engine import get_rule_engine

def clean_datasets():
    project_root = Path(__file__).parent.parent
    safe_file = project_root / 'data' / 'safe_commands_10k.txt'
    malicious_file = project_root / 'data' / 'malicious_commands_2k.txt'
    
    engine = get_rule_engine()
    
    # Read all safe commands
    with open(safe_file, 'r', encoding='utf-8') as f:
        safe_commands = [line.strip() for line in f if line.strip()]
        
    print(f"Loaded {len(safe_commands)} safe commands.")
    
    truly_safe = []
    suspicious_to_move = []
    
    # Evaluate commands
    for cmd in safe_commands:
        score, _ = engine.score_rules(cmd)
        if score >= 25.0:
            suspicious_to_move.append(cmd)
        else:
            truly_safe.append(cmd)
            
    print(f"Found {len(suspicious_to_move)} commands scoring >= 25.0.")
    print(f"Remaining safe commands: {len(truly_safe)}")
    
    if not suspicious_to_move:
        print("Dataset is already clean! No action taken.")
        return
        
    # Write back the cleaned safe list
    with open(safe_file, 'w', encoding='utf-8') as f:
        for cmd in truly_safe:
            f.write(f"{cmd}\n")
            
    # Append the suspicious ones to the malicious list
    with open(malicious_file, 'a', encoding='utf-8') as f:
        for cmd in suspicious_to_move:
            f.write(f"{cmd}\n")
            
    print(f"Successfully migrated {len(suspicious_to_move)} commands to the malicious dataset.")

if __name__ == '__main__':
    clean_datasets()
