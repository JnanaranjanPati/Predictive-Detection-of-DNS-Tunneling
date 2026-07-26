import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
from pathlib import Path
from src.utils.paths import get_path

def plot_and_save_confusion_matrix(y_true, y_pred, model_name: str) -> Path:
    """Generates, saves, and returns the path to the confusion matrix image."""
    cm = confusion_matrix(y_true, y_pred)
    
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False)
    plt.title(f'Confusion Matrix: {model_name}')
    plt.ylabel('Actual Label (0=Benign, 1=Malicious)')
    plt.xlabel('Predicted Label')
    
    save_dir = get_path("results", "metrics").parent / "confusion_matrices"
    save_dir.mkdir(parents=True, exist_ok=True)
    
    save_path = save_dir / f"{model_name}_cm.png"
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()
    
    return save_path