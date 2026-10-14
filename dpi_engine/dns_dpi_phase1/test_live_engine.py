
from dpi_engine.dpi_engine import DPIEngine


def main():

    engine = DPIEngine(
        max_detections=10000,
    )

    print("=" * 55)
    print("DNS TUNNELING DETECTION - LIVE DPI ENGINE")
    print("=" * 55)
    print("Capture mode: Continuous")
    print("Filter: UDP port 53")
    print("Press Ctrl+C to stop and save the report.")
    print("=" * 55)

    try:
        engine.process_live(
            count=0,
            timeout=None,
            packet_filter="udp port 53",
            report_filename="reports/live_dns_detection_report.json",
        )

    except Exception as error:
        print(f"\nLive capture failed: {error}")

        # Preserve the report if capture fails after processing
        # some packets.
        try:
            engine.save_report(
                "reports/live_dns_detection_report.json"
            )
            print("Current report saved.")
        except OSError as save_error:
            print(f"Could not save report: {save_error}")

        raise


if __name__ == "__main__":
    main()
