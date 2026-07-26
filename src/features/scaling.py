import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler
from src.utils.paths import get_path

def fit_and_save_scaler(X_train: pd.DataFrame) -> StandardScaler:
    """Fits the standard scaler and saves it to disk."""
    scaler = StandardScaler()
    scaler.fit(X_train)
    
    save_path = get_path("configs", "base") / "scaler.pkl"
    joblib.dump(scaler, save_path)
    return scaler

def load_scaler() -> StandardScaler:
    """Loads the pre-fitted scaler for inference/evaluation."""
    load_path = get_path("configs", "base") / "scaler.pkl"
    if not load_path.exists():
        raise FileNotFoundError("Scaler not found. Train the scaler first.")
    return joblib.load(load_path)

def scale_dataframe(df: pd.DataFrame, scaler: StandardScaler) -> pd.DataFrame:
    """Applies scaling and returns a DataFrame to preserve column names."""
    return pd.DataFrame(scaler.transform(df), columns=df.columns, index=df.index)