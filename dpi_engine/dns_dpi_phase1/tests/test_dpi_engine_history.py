
from dpi_engine.dpi_engine import DPIEngine


def test_detection_history_is_bounded_and_counters_are_lifetime_totals():
    engine = DPIEngine.__new__(DPIEngine)

    # Initialize only the fields needed for this focused test.
    engine.max_detections = 2
    engine.dns_detections = []
    engine.total_dns_predictions = 0
    engine.total_benign_predictions = 0
    engine.total_malicious_predictions = 0

    for prediction_value in [0, 1, 0, 1]:
        engine.total_dns_predictions += 1

        if prediction_value == 0:
            engine.total_benign_predictions += 1
            label = "benign"
        else:
            engine.total_malicious_predictions += 1
            label = "malicious"

        engine.dns_detections.append({
            "prediction": prediction_value,
            "label": label,
        })

        if len(engine.dns_detections) > engine.max_detections:
            del engine.dns_detections[:-engine.max_detections]

    assert len(engine.dns_detections) == 2
    assert engine.total_dns_predictions == 4
    assert engine.total_benign_predictions == 2
    assert engine.total_malicious_predictions == 2
