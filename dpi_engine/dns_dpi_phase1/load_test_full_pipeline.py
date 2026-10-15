
import gc
import json
import tracemalloc
from pathlib import Path

from dpi_engine.dpi_engine import DPIEngine


PCAP_FILES = [
    Path("pcaps/test_traffic.pcap"),
    Path("pcaps/tunneling_test.pcap"),
]

REPETITIONS = 250
MAX_DETECTIONS = 1000
REPORT_PATH = Path("reports/full_pipeline_memory_test.json")


def main():
    for path in PCAP_FILES:
        if not path.is_file():
            raise FileNotFoundError(f"PCAP not found: {path}")

    gc.collect()
    tracemalloc.start()

    engine = DPIEngine(max_detections=MAX_DETECTIONS)

    print("=" * 65)
    print("FULL-PIPELINE PCAP MEMORY TEST")
    print("=" * 65)
    print(f"Repetitions per PCAP: {REPETITIONS}")
    print(f"Detection history limit: {MAX_DETECTIONS}")
    print("Model: configured project ML pipeline")
    print()

    start_current, _ = tracemalloc.get_traced_memory()
    checkpoints = []

    for repetition in range(1, REPETITIONS + 1):
        for pcap_path in PCAP_FILES:
            engine.process_pcap(str(pcap_path))

        if repetition % 25 == 0:
            current, peak = tracemalloc.get_traced_memory()

            checkpoint = {
                "repetition": repetition,
                "packets_processed": engine.total_packets,
                "predictions": engine.total_dns_predictions,
                "retained_detections": len(engine.dns_detections),
                "current_python_mib": round(current / 1024 / 1024, 3),
                "peak_python_mib": round(peak / 1024 / 1024, 3),
            }
            checkpoints.append(checkpoint)

            print(
                f"Repetition {repetition:>3}/{REPETITIONS} | "
                f"packets={engine.total_packets:>6,} | "
                f"predictions={engine.total_dns_predictions:>5,} | "
                f"retained={len(engine.dns_detections):>4,} | "
                f"current={current / 1024 / 1024:.2f} MiB | "
                f"peak={peak / 1024 / 1024:.2f} MiB"
            )

    report = engine.report()

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    engine.save_report(str(REPORT_PATH))

    with REPORT_PATH.open("r", encoding="utf-8") as file:
        saved_report = json.load(file)

    dns_report = saved_report["dns_ml"]

    # Core retention and report checks.
    assert len(engine.dns_detections) <= MAX_DETECTIONS
    assert dns_report["retained_detection_count"] == len(
        engine.dns_detections
    )
    assert len(dns_report["detections"]) == len(
        engine.dns_detections
    )
    assert dns_report["total_transactions"] == engine.total_dns_predictions

    final_current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print()
    print("=" * 65)
    print("FULL-PIPELINE TEST SUMMARY")
    print("=" * 65)
    print(f"Packets processed: {engine.total_packets:,}")
    print(f"Lifetime ML predictions: {engine.total_dns_predictions:,}")
    print(f"Retained detections: {len(engine.dns_detections):,}")
    print(f"Lifetime benign count: {engine.total_benign_predictions:,}")
    print(f"Lifetime malicious count: {engine.total_malicious_predictions:,}")
    print(f"Initial traced Python memory: {start_current / 1024 / 1024:.2f} MiB")
    print(f"Final traced Python memory: {final_current / 1024 / 1024:.2f} MiB")
    print(f"Peak traced Python memory: {peak / 1024 / 1024:.2f} MiB")
    print(f"Report: {REPORT_PATH}")
    print("Report consistency checks: PASSED")

    if checkpoints:
        first = checkpoints[0]["current_python_mib"]
        last = checkpoints[-1]["current_python_mib"]
        print(f"First checkpoint current memory: {first:.3f} MiB")
        print(f"Last checkpoint current memory: {last:.3f} MiB")
        print(f"Checkpoint memory difference: {last - first:+.3f} MiB")

    print()
    print(
        "Note: replaying a PCAP repeats its timestamps and transactions. "
        "This is a controlled pipeline test, not a real-time throughput "
        "or real-world detection-accuracy benchmark."
    )


if __name__ == "__main__":
    main()
