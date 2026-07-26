import pandas as pd
from sklearn.ensemble import IsolationForest
from src.utils.paths import load_config

def drop_non_feature_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Strictly removes targets, identifiers, and any residual string/IP columns 
    so they cannot leak into training or crash the models.
    """
    dataset_config = load_config("dataset")
    schema = dataset_config["schema"]
    
    cols_to_drop = schema["identifiers"] + schema["targets"]
    
    # 1. Drop explicit identifiers and targets
    existing_cols_to_drop = [col for col in cols_to_drop if col in df.columns]
    df_clean = df.drop(columns=existing_cols_to_drop)
    
    # 2. Safety Net: Drop any remaining non-numeric columns (like IP addresses)
    df_clean = df_clean.select_dtypes(exclude=['object'])
    
    return df_clean

def remove_outliers_isolation_forest(X_train: pd.DataFrame, y_train: pd.Series):
    """
    Fits Isolation Forest ON THE TRAINING SET ONLY to prevent data leakage.
    Returns filtered X_train and y_train.
    """
    iso = IsolationForest(contamination=0.05, random_state=42, n_jobs=-1, verbose=1)
    # Fit and predict only on train
    yhat = iso.fit_predict(X_train) 
    
    # Keep only inliers (yhat == 1)
    mask = yhat != -1
    return X_train[mask], y_train[mask]