import shap
import matplotlib.pyplot as plt
import pandas as pd
from src.utils.paths import get_path

def generate_shap_summary(model, X_val: pd.DataFrame, model_name: str):
    """
    Actually implements SHAP (Fixing Issue #14).
    Currently supports Tree-based models (Random Forest, XGBoost, Decision Tree).
    """
    try:
        # Use TreeExplainer for tree-based models
        explainer = shap.TreeExplainer(model)
        
        # Sample the validation set to keep computation time reasonable
        X_sample = shap.sample(X_val, 500) 
        shap_values = explainer.shap_values(X_sample)
        
        # Handle binary classification outputs (some models return a list of arrays)
        if isinstance(shap_values, list):
            shap_values = shap_values[1] 
            
        plt.figure(figsize=(10, 6))
        shap.summary_plot(shap_values, X_sample, show=False)
        
        save_dir = get_path("results", "metrics").parent / "shap"
        save_dir.mkdir(parents=True, exist_ok=True)
        
        plt.tight_layout()
        plt.savefig(save_dir / f"{model_name}_shap_summary.png")
        plt.close()
        print(f"SHAP summary saved for {model_name}.")
        
    except Exception as e:
        print(f"SHAP explanation not supported or failed for {model_name}. Reason: {e}")