import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from src.utils.paths import get_path

def scale_features(X_train: pd.DataFrame, X_val: pd.DataFrame, X_test: pd.DataFrame):
    """
    Fits scaler on X_train only, then applies to val and test.
    Prevents the double-fit bug from the original GRU notebook.
    """
    scaler = StandardScaler()
    
    # Fit ONCE on train
    X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index)
    
    # Transform val and test
    X_val_scaled = pd.DataFrame(scaler.transform(X_val), columns=X_val.columns, index=X_val.index)
    X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns, index=X_test.index)
    
    # Save the fitted scaler for inference later
    scaler_path = get_path("models", "traditional").parent / "scaler.pkl"
    joblib.dump(scaler, scaler_path)

    processed_dir = get_path("data", "processed")
    X_train_scaled.to_csv(processed_dir / "X_train_scaled.csv", index=False)
    X_val_scaled.to_csv(processed_dir / "X_val_scaled.csv", index=False)
    X_test_scaled.to_csv(processed_dir / "X_test_scaled.csv", index=False)
    
    print(" Scaled X features successfully saved to data/processed!")
    
    return X_train_scaled, X_val_scaled, X_test_scaled