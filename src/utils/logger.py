import csv
import json
import hashlib
from datetime import datetime
from pathlib import Path
from src.utils.paths import get_path

def hash_feature_list(features: list) -> str:
    """Creates a deterministic hash of the feature list for traceability."""
    return hashlib.md5(json.dumps(sorted(features)).encode()).hexdigest()

def log_experiment(
    model_name: str,
    features: list,
    hyperparameters: dict,
    training_time: float,
    metrics: dict,
    model_path: Path,
    notes: str = ""
):
    """Appends a single experiment run to the master experiment_log.csv."""
    log_file = get_path("results", "metrics")
    feature_hash = hash_feature_list(features)
    
    timestamp = datetime.now().isoformat(timespec='seconds')
    experiment_id = f"EXP_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{model_name}"
    
    file_exists = log_file.exists()
    
    fieldnames = [
        "experiment_id", "model", "dataset_version", "feature_set_hash", 
        "features_used", "hyperparameters", "training_time_sec", 
        "accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", 
        "confusion_matrix_path", "model_file", "date", "notes"
    ]
    
    row = {
        "experiment_id": experiment_id,
        "model": model_name,
        "dataset_version": "v1.0", # Can be dynamic later
        "feature_set_hash": feature_hash,
        "features_used": get_path("configs", "selected_features").name,
        "hyperparameters": json.dumps(hyperparameters),
        "training_time_sec": round(training_time, 2),
        "accuracy": round(metrics.get("accuracy", 0), 4),
        "precision": round(metrics.get("macro avg", {}).get("precision", 0), 4),
        "recall": round(metrics.get("macro avg", {}).get("recall", 0), 4),
        "f1": round(metrics.get("macro avg", {}).get("f1-score", 0), 4),
        "roc_auc": round(metrics.get("roc_auc", 0), 4),
        "pr_auc": round(metrics.get("pr_auc", 0), 4),
        "confusion_matrix_path": metrics.get("cm_path", ""),
        "model_file": str(model_path.relative_to(get_path("models", "traditional").parent.parent)),
        "date": timestamp,
        "notes": notes
    }
    
    with open(log_file, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)