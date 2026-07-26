import pandas as pd
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from src.utils.paths import get_path
from src.data.cleaning import drop_non_feature_columns

def select_and_save_features(X_train: pd.DataFrame, y_train: pd.Series, top_n: int = 20):
    """
    Selects features using the Union of Top-N Mutual Information and Top-N Random Forest.
    Saves the final canonical list to configs/selected_features.json.
    """
    # Ensure no identifiers or targets leaked into X_train
    X_clean = drop_non_feature_columns(X_train)
    
    print("Calculating Mutual Information...")
    mi_scores = mutual_info_classif(X_clean, y_train, random_state=42)
    mi_series = pd.Series(mi_scores, index=X_clean.columns).sort_values(ascending=False)
    top_mi = set(mi_series.head(top_n).index)
    
    print("Calculating Random Forest Importance...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, verbose=2)
    rf.fit(X_clean, y_train)
    rf_scores = pd.Series(rf.feature_importances_, index=X_clean.columns).sort_values(ascending=False)
    top_rf = set(rf_scores.head(top_n).index)
    
    # Union of both methods (this was the LSTM/GRU approach in the original project)
    canonical_features = list(top_mi.union(top_rf))
    
    print(f"Selected {len(canonical_features)} canonical features.")
    
    # Save to config
    output_path = get_path("configs", "selected_features")
    with open(output_path, "w") as f:
        json.dump({"features": canonical_features}, f, indent=4)
        
    return canonical_features

def load_selected_features() -> list:
    """Loads the canonical feature list. All models MUST use this."""
    path = get_path("configs", "selected_features")
    if not path.exists():
        raise FileNotFoundError(f"Feature list not found at {path}. Run select_and_save_features first.")
    
    with open(path, "r") as f:
        data = json.load(f)
    return data["features"]