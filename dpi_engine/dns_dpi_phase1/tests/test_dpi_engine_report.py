
import json

from dpi_engine.dpi_engine import DPIEngine


def test_report_uses_lifetime_counts():
    engine = DPIEngine.__new__(DPIEngine)

    engine.total_packets = 10
    engine.protocol_counts = {"DNS": 4}

    engine.flow_tracker = type(
        "FakeFlowTracker",
        (),
        {"get_flows": lambda self: []},
    )()

    engine.max_detections = 2
    engine.dns_detections = [
        {"prediction": 0, "label": "benign"},
        {"prediction": 1, "label": "malicious"},
    ]

    engine.total_dns_predictions = 4
    engine.total_benign_predictions = 2
    engine.total_malicious_predictions = 2

    report = engine.report()

    assert report["total_packets"] == 10
    assert report["dns_ml"]["total_transactions"] == 4
    assert report["dns_ml"]["retained_detection_count"] == 2
    assert report["dns_ml"]["benign_transactions"] == 2
    assert report["dns_ml"]["malicious_transactions"] == 2
    assert len(report["dns_ml"]["detections"]) == 2


def test_save_report_writes_valid_json(tmp_path):
    engine = DPIEngine.__new__(DPIEngine)

    engine.total_packets = 0
    engine.protocol_counts = {}
    engine.flow_tracker = type(
        "FakeFlowTracker",
        (),
        {"get_flows": lambda self: []},
    )()

    engine.max_detections = 2
    engine.dns_detections = []
    engine.total_dns_predictions = 0
    engine.total_benign_predictions = 0
    engine.total_malicious_predictions = 0

    output_file = tmp_path / "reports" / "test_report.json"

    engine.save_report(output_file)

    with output_file.open("r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["total_packets"] == 0
    assert report["dns_ml"]["total_transactions"] == 0
    assert report["dns_ml"]["retained_detection_count"] == 0
