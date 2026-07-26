import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, precision_recall_curve, auc
from src.utils.paths import get_path

def plot_and_save_curves(y_true, y_prob, model_name: str):
    """Plots both ROC and Precision-Recall curves side-by-side."""
    if y_prob is None:
        print(f"Skipping ROC/PR curves for {model_name} (no probabilities).")
        return
        
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    roc_auc = auc(fpr, tpr)
    
    precision, recall, _ = precision_recall_curve(y_true, y_prob)
    pr_auc = auc(recall, precision)
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # ROC Curve
    ax1.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.3f})')
    ax1.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    ax1.set_xlabel('False Positive Rate')
    ax1.set_ylabel('True Positive Rate')
    ax1.set_title(f'ROC Curve: {model_name}')
    ax1.legend(loc="lower right")
    
    # PR Curve
    ax2.plot(recall, precision, color='green', lw=2, label=f'PR curve (AUC = {pr_auc:.3f})')
    ax2.set_xlabel('Recall')
    ax2.set_ylabel('Precision')
    ax2.set_title(f'Precision-Recall Curve: {model_name}')
    ax2.legend(loc="lower left")
    
    save_dir = get_path("results", "metrics").parent / "roc_curves"
    save_dir.mkdir(parents=True, exist_ok=True)
    
    plt.tight_layout()
    plt.savefig(save_dir / f"{model_name}_curves.png")
    plt.close()