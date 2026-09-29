from dpi_engine.live_capture import LiveCapture
from dpi_engine.core.packet_parser import PacketParser
from dpi_engine.dns.dns_flow_tracker import DNSFlowTracker
from dpi_engine.dns.dns_ml_pipeline import DNSMLPipeline


def main():
    capture = LiveCapture()
    parser = PacketParser()
    dns_tracker = DNSFlowTracker()
    ml_pipeline = DNSMLPipeline()

    print("Starting live DNS ML detection...")
    print("Generate DNS traffic in another terminal.")
    print("For example: nslookup google.com")
    print("Waiting for DNS traffic...\n")

    raw_packets = capture.capture(
        count=20,
        timeout=30,
        packet_filter="udp port 53",
    )

    print(f"Captured {len(raw_packets)} DNS packets\n")

    parsed_count = 0
    transaction_count = 0
    prediction_count = 0

    for raw_packet in raw_packets:
        packet = parser.parse(raw_packet)

        if packet is None:
            continue

        parsed_count += 1

        transaction = dns_tracker.process_packet(packet)

        if transaction is None or not transaction.response_received:
            continue

        transaction_count += 1

        prediction = ml_pipeline.predict_transaction(transaction)

        prediction_count += 1

        print("DNS ML DETECTION")
        print(f"  ID:         {transaction.transaction_id}")
        print(f"  Query:      {transaction.query_name}")
        print(f"  Prediction: {prediction['label']}")
        print(
            f"  Malicious probability: "
            f"{prediction['malicious_probability']:.4f}"
        )
        print()

    print("========== SUMMARY ==========")
    print(f"Captured packets:       {len(raw_packets)}")
    print(f"Parsed packets:         {parsed_count}")
    print(f"DNS transactions:       {transaction_count}")
    print(f"ML predictions:         {prediction_count}")
    print("=============================")


if __name__ == "__main__":
    main()