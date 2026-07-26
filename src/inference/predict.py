import pandas as pd
import numpy as np
import joblib
from pathlib import Path

from src.data.cleaning import drop_non_feature_columns
from src.features.feature_selection import load_selected_features
from src.utils.paths import get_path

def predict_on_dataframe(df: pd.DataFrame, model, model_name: str) -> pd.DataFrame:
    """
    Applies the full preprocessing pipeline to raw input and generates predictions.
    """
    print("1. Cleaning data...")
    X_clean = drop_non_feature_columns(df)
    
    print("2. Enforcing canonical feature selection...")
    features = load_selected_features()
    
    # Ensure all required features exist in the input dataframe
    missing_features = [f for f in features if f not in X_clean.columns]
    if missing_features:
        raise ValueError(f"Input data is missing required features: {missing_features}")
        
    X_fs = X_clean[features]
    
    print("3. Applying fitted scaling...")
    scaler_path = get_path("models", "traditional").parent / "scaler.pkl"
    scaler = joblib.load(scaler_path)
    X_scaled = pd.DataFrame(scaler.transform(X_fs), columns=X_fs.columns, index=X_fs.index)
    
    # Check if we need to reshape for GRU/LSTM (timesteps=1 tabular evaluation fix)
    if any(dl_name in model_name.lower() for dl_name in ['lstm', 'gru']):
        print(f"Reshaping input for {model_name} (timesteps=1)...")
        X_final = np.expand_dims(X_scaled.values, axis=1)
    else:
        X_final = X_scaled.values
        
    print("4. Generating predictions...")
    
    # Handle keras vs sklearn prediction outputs
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X_final)[:, 1]
        predictions = (probabilities > 0.5).astype(int)
    else:
        # Keras models
        probabilities = model.predict(X_final).flatten()
        predictions = (probabilities > 0.5).astype(int)
        
    results_df = pd.DataFrame({
        'probability_malicious': probabilities,
        'predicted_label': predictions
    })
    
    return results_df