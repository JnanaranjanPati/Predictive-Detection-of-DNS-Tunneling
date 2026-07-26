import sys
import time
import joblib
from pathlib import Path
from imblearn.over_sampling import SMOTE

sys.path.append(str(Path.cwd().parent) if Path.cwd().name == 'scripts' else str(Path.cwd()))

from src.data.loader import load_and_merge_data
from src.data.split import stratified_split
from src.data.cleaning import drop_non_feature_columns, remove_outliers_isolation_forest
from src.data.preprocessing import scale_features
from src.features.feature_selection import load_selected_features
from src.evaluation.metrics import evaluate_model
from src.utils.logger import log_experiment
from src.utils.paths import get_path

from src.models.automl import get_tpot_classifier, get_randomized_search_cv

def main():
    print("1. Loading and Splitting Data...")
    df = load_and_merge_data()
    train_df, val_df, test_df = stratified_split(df)
    
    y_train = train_df['label_encoded']
    y_val = val_df['label_encoded']

    print("2. Cleaning Data (Dropping identifiers/labels)...")
    X_train_clean = drop_non_feature_columns(train_df)
    X_val_clean = drop_non_feature_columns(val_df)
    
    print("3. Outlier Removal (Isolation Forest on Train only)...")
    X_train_inliers, y_train_inliers = remove_outliers_isolation_forest(X_train_clean, y_train)

    print("4. Applying Canonical Feature Selection...")
    features = load_selected_features()
    X_train_fs = X_train_inliers[features]
    X_val_fs = X_val_clean[features]
    
    print("5. Scaling Features...")
    X_train_scaled, X_val_scaled, _ = scale_features(X_train_fs, X_val_fs, X_val_fs)
    
    print("6. Bypassing SMOTE (Dataset is already well-balanced)...")
    X_train_final, y_train_final = X_train_scaled, y_train_inliers
    
    
    automl_dir = get_path("models", "automl")
    
    # --- 7A: Manual RandomizedSearchCV ---
    print("\n--- Training Manual RandomizedSearchCV (Random Forest) ---")
    rs_model = get_randomized_search_cv()
    
    start_time_rs = time.time()
    rs_model.fit(X_train_final, y_train_final)
    time_rs = time.time() - start_time_rs
    
    best_rf = rs_model.best_estimator_
    y_val_pred_rs = best_rf.predict(X_val_scaled)
    y_val_prob_rs = best_rf.predict_proba(X_val_scaled)[:, 1]
    
    metrics_rs = evaluate_model(y_val, y_val_pred_rs, y_val_prob_rs)
    joblib.dump(best_rf, automl_dir / "random_search_rf_best.pkl")
    
    log_experiment(
        model_name="randomized_search_rf",
        features=features,
        hyperparameters=rs_model.best_params_,
        training_time=time_rs,
        metrics=metrics_rs,
        model_path=automl_dir / "random_search_rf_best.pkl",
        notes="Manual sweep. SMOTE applied."
    )
    print(f"Random Search completed. Macro F1: {metrics_rs.get('macro avg', {}).get('f1-score', 0):.4f}")

    # --- 7B: TPOT AutoML ---
    print("\n--- Training TPOT AutoML Pipeline ---")
    tpot = get_tpot_classifier()
    
    start_time_tpot = time.time()
    tpot.fit(X_train_final, y_train_final)
    time_tpot = time.time() - start_time_tpot
    
    y_val_pred_tpot = tpot.predict(X_val_scaled)
    y_val_prob_tpot = tpot.predict_proba(X_val_scaled)[:, 1] if hasattr(tpot.fitted_pipeline_, "predict_proba") else None
    
    metrics_tpot = evaluate_model(y_val, y_val_pred_tpot, y_val_prob_tpot)
    joblib.dump(tpot.fitted_pipeline_, automl_dir / "tpot_best_pipeline.pkl")
    
    # Export valid python code using TPOT's built-in exporter
    export_path = automl_dir / "best_pipeline_code.py"
    tpot.export(str(export_path))
    
    # TPOT's internal structure can't be neatly serialized to JSON, so we log the exported script path
    log_experiment(
        model_name="automl_tpot",
        features=features,
        hyperparameters={"pipeline_code_path": str(export_path.relative_to(get_path("models", "automl").parent.parent))},
        training_time=time_tpot,
        metrics=metrics_tpot,
        model_path=automl_dir / "tpot_best_pipeline.pkl",
        notes="TPOT execution. SMOTE applied."
    )
    print(f"TPOT completed. Macro F1: {metrics_tpot.get('macro avg', {}).get('f1-score', 0):.4f}")
    print(f"Valid pipeline code exported to {export_path}")

if __name__ == "__main__":
    main()