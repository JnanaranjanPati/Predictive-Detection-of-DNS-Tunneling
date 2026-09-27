import argparse

from .dpi_engine import DPIEngine


def main():

    parser = argparse.ArgumentParser(
        description="Phase 1 DNS DPI Engine"
    )

    parser.add_argument(
        "pcap",
        help="Path to a classic PCAP file"
    )

    parser.add_argument(
        "--json-output",
        help="Path for JSON report",
        default=None
    )

    args = parser.parse_args()

    engine = DPIEngine()

    engine.process_pcap(
        args.pcap
    )

    report = engine.report()

    print("\n========== DPI REPORT ==========")

    print(
        f"Total packets: {report['total_packets']}"
    )

    print(
        f"Total flows: {report['total_flows']}"
    )

    print("\nProtocol counts:")

    for protocol, count in report[
        "protocol_counts"
    ].items():

        print(
            f"  {protocol}: {count}"
        )

    print("\nFlows:")

    for flow in report["flows"]:

        print(
            f"  {flow['source']} <-> "
            f"{flow['destination']} | "
            f"{flow['application_protocol']} | "
            f"{flow['packets']} packets"
        )

    if args.json_output:

        engine.save_report(
            args.json_output
        )

        print(
            f"\nJSON report: {args.json_output}"
        )


if __name__ == "__main__":
    main()