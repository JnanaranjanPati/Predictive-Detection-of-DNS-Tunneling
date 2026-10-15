
import gc
import tracemalloc
from pathlib import Path

from dpi_engine.dpi_engine import DPIEngine


PCAP_FILES = [
    Path("pcaps/test_traffic.pcap"),
    Path("pcaps/tunneling_test.pcap"),
]

REPETITIONS = 1500


def collection_size(obj, attribute):
    value = getattr(obj, attribute, None)
    try:
        return len(value)
    except TypeError:
        return "n/a"


def main():
    engine = DPIEngine(max_detections=1000)

    gc.collect()
    tracemalloc.start()

    print("=" * 75)
    print("FULL-PIPELINE MEMORY DIAGNOSTICS")
    print("=" * 75)

    for repetition in range(1, REPETITIONS + 1):
        for path in PCAP_FILES:
            engine.process_pcap(str(path))

        if repetition % 100 == 0:
            gc.collect()
            current, peak = tracemalloc.get_traced_memory()

            dns_tracker = engine.dns_flow_tracker
            flow_tracker = engine.flow_tracker

            print(
                f"\nRepetition {repetition:3} | "
                f"current={current / 1024 / 1024:.2f} MiB | "
                f"peak={peak / 1024 / 1024:.2f} MiB"
            )
            print(f"  Packets processed: {engine.total_packets}")
            print(f"  Lifetime predictions: {engine.total_dns_predictions}")
            print(f"  Retained detections: {len(engine.dns_detections)}")
            print(
                "  DNS completed transactions retained: "
                f"{collection_size(dns_tracker, 'transactions')}"
            )
            print(
                "  DNS pending transactions: "
                f"{collection_size(dns_tracker, 'pending_transactions')}"
            )
            print(
                "  DNS flow-query histories: "
                f"{collection_size(dns_tracker, 'flow_queries')}"
            )
            print(
                "  DNS flow-response histories: "
                f"{collection_size(dns_tracker, 'flow_responses')}"
            )
            print(
                "  Generic flows retained: "
                f"{collection_size(flow_tracker, 'flows')}"
            )

    tracemalloc.stop()


if __name__ == "__main__":
    main()
