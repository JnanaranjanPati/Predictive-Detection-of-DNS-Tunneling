from sklearn.metrics import classification_report, roc_auc_score, average_precision_score

def evaluate_model(y_true, y_pred, y_prob=None) -> dict:
    """Calculates classification report + AUC metrics safely."""
    metrics = classification_report(y_true, y_pred, output_dict=True)
    
    if y_prob is not None:
        try:
            # Assuming binary classification (1=malicious)
            metrics["roc_auc"] = roc_auc_score(y_true, y_prob)
            metrics["pr_auc"] = average_precision_score(y_true, y_prob)
        except Exception:
            metrics["roc_auc"] = 0.0
            metrics["pr_auc"] = 0.0
    else:
        metrics["roc_auc"] = 0.0
        metrics["pr_auc"] = 0.0
        
    return metrics