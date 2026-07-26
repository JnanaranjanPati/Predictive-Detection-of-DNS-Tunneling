import pandas as pd
from src.utils.paths import get_path

def generate_comparison_report():
    """CLI equivalent of the Model Comparison Notebook."""
    log_path = get_path("results", "metrics")
    if not log_path.exists():
        print("No experiment logs found.")
        return
        
    df = pd.read_csv(log_path)
    df['date'] = pd.to_datetime(df['date'])
    df = df.sort_values('date').drop_duplicates('model', keep='last')
    
    print("\n" + "="*50)
    print("FINAL MODEL COMPARISON REPORT")
    print("="*50)
    
    summary = df[['model', 'f1', 'roc_auc', 'pr_auc', 'training_time_sec']].sort_values(by='f1', ascending=False)
    print(summary.to_string(index=False))
    print("="*50)

if __name__ == "__main__":
    generate_comparison_report()