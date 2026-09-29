from typing import Iterable

from dpi_engine.dns.dns_feature_extractor import (
    build_dns_features,
    build_feature_vector,
    FEATURE_ORDER,
)
from dpi_engine.ml.predictor import DNSTunnelingPredictor


class DNSMLPipeline:
    """
    Connects the DNS flow information produced by the DPI engine
    to the existing DNS feature extractor and trained XGBoost model.

    Pipeline:

        DNS flow information
            ↓
        Existing feature extractor
            ↓
        23-feature vector
            ↓
        Existing StandardScaler
            ↓
        Existing XGBoost model
            ↓
        Benign / Malicious
    """

    def __init__(self, predictor: DNSTunnelingPredictor | None = None):
        self.predictor = predictor or DNSTunnelingPredictor()

    def extract_features(
        self,
        *,
        domain: str,
        packet_lengths: Iterable[float],
        duration: float,
        src_port: int,
        sending_bytes: float,
        ttl_values: Iterable[float],
        answer_record_types: Iterable[int],
    ) -> dict[str, float]:
        """
        Build the exact feature dictionary used by the existing model.
        """

        features = build_dns_features(
            domain=domain,
            packet_lengths=packet_lengths,
            duration=duration,
            src_port=src_port,
            sending_bytes=sending_bytes,
            ttl_values=ttl_values,
            answer_record_types=answer_record_types,
        )

        if not isinstance(features, dict):
            raise TypeError(
                "build_dns_features() must return a dictionary."
            )

        missing = [
            feature
            for feature in FEATURE_ORDER
            if feature not in features
        ]

        if missing:
            raise ValueError(
                "Feature extractor returned an incomplete feature set.\n"
                "Missing features:\n"
                + "\n".join(f"  - {feature}" for feature in missing)
            )

        return features

    def build_vector(
        self,
        *,
        domain: str,
        packet_lengths: Iterable[float],
        duration: float,
        src_port: int,
        sending_bytes: float,
        ttl_values: Iterable[float],
        answer_record_types: Iterable[int],
    ) -> list[float]:
        """
        Build the canonical 23-feature vector.

        This uses the existing build_feature_vector() implementation
        rather than manually constructing the vector.
        """

        vector = build_feature_vector(
            domain=domain,
            packet_lengths=packet_lengths,
            duration=duration,
            src_port=src_port,
            sending_bytes=sending_bytes,
            ttl_values=ttl_values,
            answer_record_types=answer_record_types,
        )

        if len(vector) != len(FEATURE_ORDER):
            raise ValueError(
                f"Feature vector has {len(vector)} values, "
                f"but the model expects {len(FEATURE_ORDER)}."
            )

        return vector

    def predict(
        self,
        *,
        domain: str,
        packet_lengths: Iterable[float],
        duration: float,
        src_port: int,
        sending_bytes: float,
        ttl_values: Iterable[float],
        answer_record_types: Iterable[int],
    ) -> dict:
        """
        Complete:

            DNS flow
                ↓
            Feature extraction
                ↓
            Scaling
                ↓
            XGBoost prediction
        """

        # Materialize iterables once because some callers may provide
        # generators instead of lists.
        packet_lengths = list(packet_lengths)
        ttl_values = list(ttl_values)
        answer_record_types = list(answer_record_types)

        # ---------------------------------------------------------
        # 1. Build existing project's 23 DNS features
        # ---------------------------------------------------------
        features = self.extract_features(
            domain=domain,
            packet_lengths=packet_lengths,
            duration=duration,
            src_port=src_port,
            sending_bytes=sending_bytes,
            ttl_values=ttl_values,
            answer_record_types=answer_record_types,
        )

        # ---------------------------------------------------------
        # 2. Build canonical feature vector
        # ---------------------------------------------------------
        feature_vector = self.build_vector(
            domain=domain,
            packet_lengths=packet_lengths,
            duration=duration,
            src_port=src_port,
            sending_bytes=sending_bytes,
            ttl_values=ttl_values,
            answer_record_types=answer_record_types,
        )

        # ---------------------------------------------------------
        # 3. Existing scaler + existing XGBoost
        # ---------------------------------------------------------
        prediction = self.predictor.predict_features(features)

        # ---------------------------------------------------------
        # 4. Add DPI pipeline information
        # ---------------------------------------------------------
        prediction["feature_vector"] = feature_vector
        prediction["feature_count"] = len(feature_vector)

        return prediction

    def predict_transaction(self, transaction) -> dict:
        """
        Run ML prediction directly from a completed DNSTransaction.

        The transaction must contain:
            query_name
            packet_lengths
            response_time
            client_port
            sending_bytes
            ttl_values
            answer_record_types
        """

        if not transaction.response_received:
            raise ValueError(
                "Cannot predict an incomplete DNS transaction."
            )

        duration = transaction.response_time

        if duration is None:
            raise ValueError(
                "DNS transaction does not have a valid response time."
            )

        result = self.predict(
            domain=transaction.query_name,
            packet_lengths=transaction.packet_lengths,
            duration=duration,
            src_port=transaction.client_port,
            sending_bytes=transaction.sending_bytes,
            ttl_values=transaction.ttl_values,
            answer_record_types=transaction.answer_record_types,
        )

        # Add transaction-level metadata to the result.
        result["transaction_id"] = transaction.transaction_id
        result["client_ip"] = transaction.client_ip
        result["client_port"] = transaction.client_port
        result["server_ip"] = transaction.server_ip
        result["server_port"] = transaction.server_port
        result["domain"] = transaction.query_name
        result["duration"] = duration

        return result