from dpi_engine.dpi_engine import DPIEngine


def main():

    engine = DPIEngine()

    engine.process_live(
        count=20,
        timeout=30,
        packet_filter="udp port 53",
    )

    engine.save_report(
        "reports/live_dns_detection_report.json"
    )

    print(
        "\nReport saved to:"
        " reports/live_dns_detection_report.json"
    )


if __name__ == "__main__":
    main()