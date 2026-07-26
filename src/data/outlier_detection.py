import pandas as pd
from sklearn.ensemble import IsolationForest
from src.utils.paths import load_config

def remove_outliers(X_train: pd.DataFrame, y_train: pd.Series):
    """Isolates outlier detection logic using configs."""
    config = load_config("preprocessing")
    contam = config.get("outlier_detection", {}).get("contamination", 0.05)
    
    iso = IsolationForest(contamination=contam, random_state=42, n_jobs=-1)
    yhat = iso.fit_predict(X_train) 
    
    mask = yhat != -1
    return X_train[mask], y_train[mask]