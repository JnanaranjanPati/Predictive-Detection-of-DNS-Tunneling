from pathlib import Path

from dpi_engine.dpi_engine import DPIEngine


PCAP_PATH = Path("pcaps/test_traffic.pcap")


def test_multiple_dns_transactions_ml_inference():
    """
    Regression test for the complete DNS -> feature -> ML pipeline.

    Verifies that:
    1. The PCAP is processed successfully.
    2. Four DNS transactions are completed.
    3. Each transaction receives exactly one ML prediction.
    4. Every prediction contains exactly 23 features.
    5. Transaction IDs and domains are preserved correctly.
    """

    assert PCAP_PATH.exists(), (
        f"Test PCAP not found: {PCAP_PATH}. "
        "Run generate_test_pcap.py first."
    )

    engine = DPIEngine()
    engine.process_pcap(PCAP_PATH)

    report = engine.report()

    # ---------------------------------------------------------
    # General DPI validation
    # ---------------------------------------------------------

    assert report["total_packets"] == 14
    assert report["total_flows"] == 7

    # ---------------------------------------------------------
    # DNS ML validation
    # ---------------------------------------------------------

    dns_ml = report["dns_ml"]

    assert dns_ml["total_transactions"] == 4

    detections = dns_ml["detections"]

    # Exactly one prediction per completed DNS transaction.
    assert len(detections) == 4

    # ---------------------------------------------------------
    # Transaction identity validation
    # ---------------------------------------------------------

    expected_transactions = {
        100: "example.com",
        101: "google.com",
        102: "openai.com",
        103: "www.github.com",
    }

    actual_transactions = {
        detection["transaction_id"]: detection["domain"]
        for detection in detections
    }

    assert actual_transactions == expected_transactions

    # ---------------------------------------------------------
    # ML feature validation
    # ---------------------------------------------------------

    for detection in detections:

        # Existing XGBoost model expects exactly 23 features.
        assert detection["feature_count"] == 23

        assert len(detection["feature_vector"]) == 23

        assert len(detection["features"]) == 23

        # Prediction must be binary.
        assert detection["prediction"] in (0, 1)

        # Label must correspond to the prediction.
        if detection["prediction"] == 0:
            assert detection["label"] == "benign"
        else:
            assert detection["label"] == "malicious"

        # Probability must be in [0, 1].
        probability = detection["malicious_probability"]

        assert 0.0 <= probability <= 1.0

    # ---------------------------------------------------------
    # Expected result for the current synthetic test PCAP
    # ---------------------------------------------------------

    assert dns_ml["benign_transactions"] == 4
    assert dns_ml["malicious_transactions"] == 0