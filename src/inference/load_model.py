import joblib
from pathlib import Path
from tensorflow.keras.models import load_model as load_keras_model

def load_trained_model(model_path: Path):
    """
    Dynamically loads either a standard ML model (.pkl) or a Deep Learning model (.keras).
    """
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found at {model_path}")
        
    if model_path.suffix == '.keras':
        print(f"Loading Keras Deep Learning model from {model_path.name}...")
        return load_keras_model(model_path)
    elif model_path.suffix == '.pkl':
        print(f"Loading scikit-learn/TPOT model from {model_path.name}...")
        return joblib.load(model_path)
    else:
        raise ValueError(f"Unsupported model extension '{model_path.suffix}'. Expected .pkl or .keras")