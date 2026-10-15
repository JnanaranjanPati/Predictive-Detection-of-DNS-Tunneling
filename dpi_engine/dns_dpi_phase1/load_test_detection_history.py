
import gc
import json
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import dpi_engine.dpi_engine as dpi_module


TOTAL_PREDICTIONS = 50_000
MAX_DETECTIONS = 1_000
REPORT_PATH = Path("reports/load_test_detection_history.json")


class FakeDNSMLPipeline:
    """Deterministic predictor for testing history and counters."""

    def predict_transaction(self, transaction):
        number = transaction.transaction_id
        prediction = 1 if number % 10 == 0 else 0

        return {
            "prediction": prediction,
            "label": "MALICIOUS" if prediction else "BENIGN",
            "malicious_probability": 0.95 if prediction else 0.05,
        }


def main():
    # Replace the predictor only for this test process.
    dpi_module.DNSMLPipeline = FakeDNSMLPipeline

    engine = dpi_module.DPIEngine(max_detections=MAX_DETECTIONS)

    # Bypass packet parsing and flow tracking so this test focuses
    # on prediction history, lifetime counters, and report consistency.
    fake_packet = SimpleNamespace(application_protocol=None)
    engine.parser.parse = lambda raw_packet: fake_packet
    engine.detector.detect = lambda packet: "DNS"
    engine.flow_tracker.process = lambda packet: None

    sequence = {"value": 0}

    def fake_process_packet(packet):
        sequence["value"] += 1
        number = sequence["value"]

        return SimpleNamespace(
            response_received=True,
            transaction_id=number,
            query_name=f"load-{number}.example.com",
            client_ip="192.0.2.10",
            client_port=40000 + (number % 20000),
            server_ip="192.0.2.53",
            server_port=53,
            response_time=0.01,
        )

    engine.dns_flow_tracker.process_packet = fake_process_packet

    gc.collect()
    tracemalloc.start()
    initial_memory, _ = tracemalloc.get_traced_memory()

    print("=" * 60)
    print("DNS DPI ENGINE - SUSTAINED-LOAD HISTORY TEST")
    print("=" * 60)
    print(f"Predictions to simulate: {TOTAL_PREDICTIONS:,}")
    print(f"History limit: {MAX_DETECTIONS:,}")
    print("Predictor: simulated; real XGBoost is not loaded")
    print()

    for number in range(1, TOTAL_PREDICTIONS + 1):
        engine._process_raw_packet(
            SimpleNamespace(data=b"simulated-packet")
        )

        if number % 10_000 == 0:
            current, peak = tracemalloc.get_traced_memory()
            print(
                f"Processed {number:>7,} | "
                f"retained={len(engine.dns_detections):>4,} | "
                f"current={current / 1024 / 1024:.2f} MiB | "
                f"peak={peak / 1024 / 1024:.2f} MiB"
            )

    report = engine.report()
    dns_report = report["dns_ml"]

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    engine.save_report(str(REPORT_PATH))

    final_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Verify the retention limit and lifetime counters.
    assert engine.total_dns_predictions == TOTAL_PREDICTIONS
    assert len(engine.dns_detections) == MAX_DETECTIONS
    assert engine.total_benign_predictions == 45_000
    assert engine.total_malicious_predictions == 5_000

    assert dns_report["total_transactions"] == TOTAL_PREDICTIONS
    assert dns_report["retained_detection_count"] == MAX_DETECTIONS
    assert len(dns_report["detections"]) == MAX_DETECTIONS

    retained_ids = [
        item["transaction_id"] for item in engine.dns_detections
    ]
    assert retained_ids == list(
        range(
            TOTAL_PREDICTIONS - MAX_DETECTIONS + 1,
            TOTAL_PREDICTIONS + 1,
        )
    )

    # Confirm the saved JSON report is consistent too.
    with REPORT_PATH.open("r", encoding="utf-8") as file:
        saved_report = json.load(file)

    saved_dns = saved_report["dns_ml"]
    assert saved_dns["total_transactions"] == TOTAL_PREDICTIONS
    assert saved_dns["retained_detection_count"] == MAX_DETECTIONS
    assert len(saved_dns["detections"]) == MAX_DETECTIONS

    print()
    print("=" * 60)
    print("LOAD TEST RESULTS")
    print("=" * 60)
    print(f"Predictions processed: {engine.total_dns_predictions:,}")
    print(f"Detections retained: {len(engine.dns_detections):,}")
    print(f"Lifetime benign count: {engine.total_benign_predictions:,}")
    print(f"Lifetime malicious count: {engine.total_malicious_predictions:,}")
    print(f"Initial Python memory: {initial_memory / 1024 / 1024:.2f} MiB")
    print(f"Final Python memory: {final_memory / 1024 / 1024:.2f} MiB")
    print(f"Peak Python memory: {peak_memory / 1024 / 1024:.2f} MiB")
    print(f"Report: {REPORT_PATH}")
    print("Saved JSON report: validated")
    print("All load-test assertions: PASSED")
    print()
    print(
        "This test simulates predictions. It does not measure "
        "real packet-capture throughput or real-model inference speed."
    )


if __name__ == "__main__":
    main()
