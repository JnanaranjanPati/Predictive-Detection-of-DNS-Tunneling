import sys
import time
import numpy as np
from pathlib import Path
from imblearn.over_sampling import SMOTE
from tensorflow.keras.callbacks import EarlyStopping

sys.path.append(str(Path.cwd().parent) if Path.cwd().name == 'scripts' else str(Path.cwd()))

from src.data.loader import load_and_merge_data
from src.data.split import stratified_split
from src.data.cleaning import drop_non_feature_columns, remove_outliers_isolation_forest
from src.data.preprocessing import scale_features
from src.features.feature_selection import load_selected_features
from src.evaluation.metrics import evaluate_model
from src.utils.logger import log_experiment
from src.utils.paths import get_path

from src.models.dense_nn import get_model as get_dnn
from src.models.lstm import get_model as get_lstm
from src.models.gru import get_model as get_gru

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

    print("4. Loading Canonical Feature Selection...")
    features = load_selected_features()
    X_train_fs = X_train_inliers[features]
    X_val_fs = X_val_clean[features]
    
    print("5. Scaling Features...")
    X_train_scaled, X_val_scaled, _ = scale_features(X_train_fs, X_val_fs, X_val_fs) # Dummy test set just to pass arg
    
    print("6. Handling Class Imbalance (SMOTE)...")
    smote = SMOTE(random_state=42)
    X_train_final, y_train_final = smote.fit_resample(X_train_scaled, y_train_inliers)
    
    input_dim = X_train_final.shape[1]
    
    models = {
        "dense_nn": get_dnn(input_dim),
        "lstm": get_lstm(input_dim),
        "gru": get_gru(input_dim)
    }
    
    models_dir = get_path("models", "deep_learning")
    early_stop = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
    
    for name, model in models.items():
        print(f"\n--- Training {name.upper()} ---")
        
        # Reshape for recurrent models (timesteps=1 fix)
        if name in ['lstm', 'gru']:
            X_tr_model = np.expand_dims(X_train_final.values, axis=1)
            X_val_model = np.expand_dims(X_val_scaled.values, axis=1)
            hyperparam_notes = "timesteps=1 (Tabular evaluation); SMOTE applied."
        else:
            X_tr_model = X_train_final.values
            X_val_model = X_val_scaled.values
            hyperparam_notes = "SMOTE applied."
            
        start_time = time.time()
        
        # Train
        history = model.fit(
            X_tr_model, y_train_final,
            validation_data=(X_val_model, y_val),
            epochs=30,
            batch_size=256,
            callbacks=[early_stop],
            verbose=1
        )
        training_time = time.time() - start_time
        
        # Predict on validation set
        y_val_prob = model.predict(X_val_model).flatten()
        y_val_pred = (y_val_prob > 0.5).astype(int)
        
        # Evaluate
        metrics = evaluate_model(y_val, y_val_pred, y_val_prob)
        
        # Save Model Artifact (.keras format is modern standard)
        model_path = models_dir / f"{name}_best.keras"
        model.save(model_path)
        
        # Format hyperparameters for logging
        hparams = {
            "epochs_run": len(history.history['loss']),
            "batch_size": 256,
            "architecture": [layer.__class__.__name__ for layer in model.layers]
        }
        
        # Log to experiment_log.csv
        log_experiment(
            model_name=name,
            features=features,
            hyperparameters=hparams,
            training_time=training_time,
            metrics=metrics,
            model_path=model_path,
            notes=hyperparam_notes
        )
        print(f"{name} completed. Macro F1: {metrics.get('macro avg', {}).get('f1-score', 0):.4f}")

if __name__ == "__main__":
    main()