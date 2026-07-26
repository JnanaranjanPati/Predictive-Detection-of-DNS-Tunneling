import sys
import time
import joblib
import os
from pathlib import Path

# Fix for the Windows joblib/loky CPU counting warning
os.environ['LOKY_MAX_CPU_COUNT'] = '4'  

sys.path.append(str(Path.cwd().parent) if Path.cwd().name == 'scripts' else str(Path.cwd()))

from src.data.loader import load_and_merge_data
from src.data.split import stratified_split
from src.data.cleaning import drop_non_feature_columns, remove_outliers_isolation_forest
from src.data.preprocessing import scale_features
from src.features.feature_selection import select_and_save_features, load_selected_features
from src.evaluation.metrics import evaluate_model
from src.utils.logger import log_experiment
from src.utils.paths import get_path

from src.models.decision_tree import get_model as get_dt
from src.models.random_forest import get_model as get_rf
from src.models.svm import get_model as get_svm
from src.models.xgboost import get_model as get_xgb

def main():
    print("1. Loading and Splitting Data...")
    df = load_and_merge_data()
    train_df, val_df, test_df = stratified_split(df)
    
    y_train = train_df['label_encoded']
    y_val = val_df['label_encoded']
    y_test = test_df['label_encoded']

    print("2. Cleaning Data (Dropping identifiers/labels)...")
    X_train_clean = drop_non_feature_columns(train_df)
    X_val_clean = drop_non_feature_columns(val_df)
    X_test_clean = drop_non_feature_columns(test_df)
    
    print("3. Outlier Removal (Isolation Forest on Train only)...")
    X_train_inliers, y_train_inliers = remove_outliers_isolation_forest(X_train_clean, y_train)

    print("4. Applying Canonical Feature Selection (Calculating and saving to JSON)...")
    features = select_and_save_features(X_train_inliers, y_train_inliers)
    
    X_train_fs = X_train_inliers[features]
    X_val_fs = X_val_clean[features]
    X_test_fs = X_test_clean[features]
    
    print("5. Scaling Features...")
    X_train_scaled, X_val_scaled, X_test_scaled = scale_features(X_train_fs, X_val_fs, X_test_fs)
    processed_dir = get_path("data", "processed")
    y_train.to_csv(processed_dir / "y_train.csv", index=False)
    y_val.to_csv(processed_dir / "y_val.csv", index=False)
    y_test.to_csv(processed_dir / "y_test.csv", index=False)
    print(" Target labels successfully saved to data/processed!")


    
    print("6. Bypassing SMOTE (Dataset is already well-balanced)...")
    # We skip SMOTE entirely to save hours of compute time
    X_train_final, y_train_final = X_train_scaled, y_train_inliers
    
    models = {
        "decision_tree": get_dt(),
        "random_forest": get_rf(),
        "svm": get_svm(),
        "xgboost": get_xgb()
    }
    
    models_dir = get_path("models", "traditional")
    
    for name, model in models.items():
        print(f"\n--- Training {name} ---")
        start_time = time.time()
        
        # Train
        model.fit(X_train_final, y_train_final)
        training_time = time.time() - start_time
        
        # Predict on validation set for metrics logging
        y_val_pred = model.predict(X_val_scaled)
        y_val_prob = model.predict_proba(X_val_scaled)[:, 1] if hasattr(model, "predict_proba") else None
        
        # Evaluate
        metrics = evaluate_model(y_val, y_val_pred, y_val_prob)
        
        # Save Model Artifact
        model_path = models_dir / f"{name}_best.pkl"
        joblib.dump(model, model_path)
        
        # Log to experiment_log.csv
        log_experiment(
            model_name=name,
            features=features,
            hyperparameters=model.get_params(),
            training_time=training_time,
            metrics=metrics,
            model_path=model_path,
            notes="Natural balance used. Evaluated on Validation set."
        )
        print(f"{name} completed. Macro F1: {metrics.get('macro avg', {}).get('f1-score', 0):.4f}")

if __name__ == "__main__":
    main()