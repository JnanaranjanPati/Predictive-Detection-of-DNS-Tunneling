
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



from types import SimpleNamespace

import dpi_engine.dpi_engine as dpi_module


def test_detection_history_stays_bounded_under_load(monkeypatch):
    """Keep only the latest detections while counting every prediction."""

    class FakeDNSMLPipeline:
        def predict_transaction(self, transaction):
            return {
                "prediction": 0,
                "label": "BENIGN",
                "malicious_probability": 0.05,
            }

    # Avoid loading the real model; this test targets history management.
    monkeypatch.setattr(
        dpi_module,
        "DNSMLPipeline",
        FakeDNSMLPipeline,
    )

    engine = dpi_module.DPIEngine(max_detections=10)

    # Replace packet-processing dependencies so each test packet
    # completes one DNS transaction deterministically.
    fake_packet = SimpleNamespace(application_protocol=None)
    engine.parser.parse = lambda raw_packet: fake_packet
    engine.detector.detect = lambda packet: "DNS"
    engine.flow_tracker.process = lambda packet: None

    transaction_number = {"value": 0}

    def fake_process_packet(packet):
        transaction_number["value"] += 1
        number = transaction_number["value"]

        return SimpleNamespace(
            response_received=True,
            transaction_id=number,
            query_name=f"test-{number}.example.com",
            client_ip="192.0.2.10",
            client_port=40000 + number,
            server_ip="192.0.2.53",
            server_port=53,
            response_time=0.01,
        )

    engine.dns_flow_tracker.process_packet = fake_process_packet

    # Process 25 completed transactions with a retention limit of 10.
    for number in range(1, 26):
        engine._process_raw_packet(
            SimpleNamespace(data=b"test-packet")
        )

    # Only the latest 10 detections should remain in memory.
    assert len(engine.dns_detections) == 10

    retained_ids = [
        detection["transaction_id"]
        for detection in engine.dns_detections
    ]
    assert retained_ids == list(range(16, 26))

    # Lifetime statistics must include all 25 predictions.
    assert engine.total_dns_predictions == 25
    assert engine.total_benign_predictions == 25
    assert engine.total_malicious_predictions == 0

    # The report must distinguish lifetime totals from retained history.
    report = engine.report()
    dns_report = report["dns_ml"]

    assert dns_report["total_transactions"] == 25
    assert dns_report["retained_detection_count"] == 10
    assert dns_report["benign_transactions"] == 25
    assert dns_report["malicious_transactions"] == 0
    assert len(dns_report["detections"]) == 10
