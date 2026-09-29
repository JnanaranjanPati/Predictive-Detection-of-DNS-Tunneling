from pathlib import Path
import json
import joblib
import pandas as pd

from dpi_engine.dns.dns_feature_extractor import FEATURE_ORDER


class DNSTunnelingPredictor:
    """
    Loads the existing trained DNS tunneling model and scaler.

    Pipeline:
        23 raw DNS features
        -> StandardScaler
        -> XGBoost
        -> prediction
    """

    def __init__(
        self,
        project_root: Path | None = None,
        model_path: Path | None = None,
        scaler_path: Path | None = None,
    ):
        if project_root is None:
            # dns_dpi_phase1/
            project_root = Path(__file__).resolve().parents[2]

        self.project_root = project_root

        if model_path is None:
            model_path = (
                self.project_root.parent.parent
                / "models"
                / "traditional"
                / "xgboost_best.pkl"
            )

        if scaler_path is None:
            scaler_path = (
                self.project_root.parent.parent
                / "models"
                / "scaler.pkl"
            )

        self.model_path = Path(model_path)
        self.scaler_path = Path(scaler_path)

        self._validate_paths()

        print(f"Loading XGBoost model: {self.model_path}")
        self.model = joblib.load(self.model_path)

        print(f"Loading scaler: {self.scaler_path}")
        self.scaler = joblib.load(self.scaler_path)

        self._validate_feature_order()

        print("DNS tunneling predictor loaded successfully.")

    def _validate_paths(self):
        """Make sure the existing ML artifacts actually exist."""

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"XGBoost model not found:\n{self.model_path}"
            )

        if not self.scaler_path.exists():
            raise FileNotFoundError(
                f"Scaler not found:\n{self.scaler_path}"
            )

    def _validate_feature_order(self):
        """
        Validate that the scaler expects the same 23 features
        used by the existing DNS feature extractor.
        """

        expected_count = len(FEATURE_ORDER)

        if hasattr(self.scaler, "n_features_in_"):
            if self.scaler.n_features_in_ != expected_count:
                raise ValueError(
                    f"Feature count mismatch.\n"
                    f"Feature extractor: {expected_count}\n"
                    f"Scaler expects: {self.scaler.n_features_in_}"
                )

        if hasattr(self.model, "n_features_in_"):
            if self.model.n_features_in_ != expected_count:
                raise ValueError(
                    f"Feature count mismatch.\n"
                    f"Feature extractor: {expected_count}\n"
                    f"Model expects: {self.model.n_features_in_}"
                )

    def prepare_features(self, features: dict) -> pd.DataFrame:
        """
        Convert a DNS feature dictionary into the exact feature
        order expected by the existing model.
        """

        missing = [
            feature
            for feature in FEATURE_ORDER
            if feature not in features
        ]

        if missing:
            raise ValueError(
                "Missing required DNS features:\n"
                + "\n".join(f"  - {feature}" for feature in missing)
            )

        # IMPORTANT:
        # Never rely on dictionary insertion order.
        # Explicitly construct the canonical model feature order.
        row = {
            feature: features[feature]
            for feature in FEATURE_ORDER
        }

        dataframe = pd.DataFrame([row], columns=FEATURE_ORDER)

        return dataframe

    def predict_features(self, features: dict) -> dict:
        """
        Predict whether one DNS flow is benign or malicious.

        Input:
            Raw 23-feature dictionary.

        Output:
            Prediction information including probability.
        """

        X = self.prepare_features(features)

        # Apply the SAME scaler used during training.
        X_scaled = self.scaler.transform(X)

        prediction = int(self.model.predict(X_scaled)[0])

        probability = None

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(X_scaled)[0]
            probability = float(probabilities[1])

        label = "malicious" if prediction == 1 else "benign"

        return {
            "prediction": prediction,
            "label": label,
            "malicious_probability": probability,
            "features": {
                feature: float(X.iloc[0][feature])
                for feature in FEATURE_ORDER
            },
        }

    def predict_dataframe(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        """
        Predict multiple DNS flows.

        The dataframe must contain all features in FEATURE_ORDER.
        """

        missing = [
            feature
            for feature in FEATURE_ORDER
            if feature not in dataframe.columns
        ]

        if missing:
            raise ValueError(
                "Missing required DNS features:\n"
                + "\n".join(f"  - {feature}" for feature in missing)
            )

        X = dataframe[FEATURE_ORDER]

        X_scaled = self.scaler.transform(X)

        predictions = self.model.predict(X_scaled)

        result = dataframe.copy()

        result["prediction"] = predictions
        result["label"] = [
            "malicious" if value == 1 else "benign"
            for value in predictions
        ]

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(X_scaled)

            result["malicious_probability"] = probabilities[:, 1]

        return result

    def model_info(self) -> dict:
        """Return basic information about the loaded model."""

        return {
            "model": "XGBoost",
            "model_path": str(self.model_path),
            "scaler_path": str(self.scaler_path),
            "feature_count": len(FEATURE_ORDER),
            "features": FEATURE_ORDER,
        }