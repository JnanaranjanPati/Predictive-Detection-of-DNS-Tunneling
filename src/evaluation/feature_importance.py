import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from src.utils.paths import get_path

def plot_tree_importance(model, feature_names: list, model_name: str):
    """Extracts and plots native feature importances for tree-based models."""
    if not hasattr(model, 'feature_importances_'):
        print(f"{model_name} does not support native feature_importances_.")
        return
        
    importances = model.feature_importances_
    df_imp = pd.DataFrame({'Feature': feature_names, 'Importance': importances})
    df_imp = df_imp.sort_values(by='Importance', ascending=False).head(20)
    
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df_imp, x='Importance', y='Feature', palette='viridis')
    plt.title(f'Top 20 Feature Importances: {model_name}')
    
    save_dir = get_path("results", "metrics").parent / "feature_importance"
    save_dir.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(save_dir / f"{model_name}_importance.png")
    plt.close()