import sys
import argparse
import pandas as pd
from pathlib import Path

sys.path.append(str(Path.cwd().parent) if Path.cwd().name == 'scripts' else str(Path.cwd()))

from src.inference.load_model import load_trained_model
from src.inference.predict import predict_on_dataframe
from src.evaluation.metrics import evaluate_model
from src.utils.paths import get_path

def main():
    parser = argparse.ArgumentParser(description="Run inference and evaluate a trained model on a dataset.")
    parser.add_argument("--data", type=str, required=True, help="Path to the evaluation CSV file.")
    parser.add_argument("--model", type=str, required=True, help="Path to the trained model artifact (.pkl or .keras).")
    parser.add_argument("--output", type=str, default="predictions.csv", help="Filename to save predictions.")
    
    args = parser.parse_args()
    
    data_path = Path(args.data)
    model_path = Path(args.model)
    
    if not data_path.exists():
        print(f"Error: Data file not found at {data_path}")
        sys.exit(1)
        
    print(f"Loading data from {data_path.name}...")
    df = pd.read_csv(data_path)
    
    model = load_trained_model(model_path)
    
    # Generate predictions
    results_df = predict_on_dataframe(df, model, model_name=model_path.stem)
    
    # Save output
    output_dir = get_path("results", "metrics").parent / "predictions"
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / args.output
    
    results_df.to_csv(out_file, index=False)
    print(f"Predictions saved to {out_file}")
    
    # If the input data has true labels, run evaluation
    if 'label_encoded' in df.columns:
        print("\n--- Evaluation Metrics ---")
        y_true = df['label_encoded']
        metrics = evaluate_model(y_true, results_df['predicted_label'], results_df['probability_malicious'])
        
        print(f"Accuracy:  {metrics.get('accuracy', 0):.4f}")
        print(f"Macro F1:  {metrics.get('macro avg', {}).get('f1-score', 0):.4f}")
        print(f"ROC-AUC:   {metrics.get('roc_auc', 0):.4f}")
        print(f"PR-AUC:    {metrics.get('pr_auc', 0):.4f}")
    else:
        print("\nNo 'label_encoded' column found in input data. Skipping metric evaluation.")

if __name__ == "__main__":
    main()