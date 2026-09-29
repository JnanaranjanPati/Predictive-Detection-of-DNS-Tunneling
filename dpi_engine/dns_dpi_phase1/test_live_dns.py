from dpi_engine.live_capture import LiveCapture
from dpi_engine.core.packet_parser import PacketParser
from dpi_engine.dns.dns_flow_tracker import DNSFlowTracker


def main():
    capture = LiveCapture()
    parser = PacketParser()
    dns_tracker = DNSFlowTracker()

    print("Starting live DNS capture...")
    print("Run 'nslookup google.com' in another terminal.")
    print("Waiting for DNS traffic...\n")

    raw_packets = capture.capture(
        count=10,
        timeout=30,
        packet_filter="udp port 53",
    )

    print(f"Captured {len(raw_packets)} DNS packets\n")

    parsed_count = 0
    transaction_count = 0

    for raw_packet in raw_packets:
        packet = parser.parse(raw_packet)

        if packet is None:
            continue

        parsed_count += 1

        transaction = dns_tracker.process_packet(packet)

        if transaction is not None:
            if transaction.response_received:
                transaction_count += 1

                print("DNS TRANSACTION COMPLETED")
                print(f"  ID:       {transaction.transaction_id}")
                print(f"  Query:    {transaction.query_name}")
                print(f"  Client:   {transaction.client_ip}:{transaction.client_port}")
                print(f"  Server:   {transaction.server_ip}:{transaction.server_port}")
                print(f"  Response: {transaction.response_received}")
                print(f"  Duration: {transaction.response_time}")
                print()

    print("========== SUMMARY ==========")
    print(f"Captured packets:       {len(raw_packets)}")
    print(f"Parsed packets:         {parsed_count}")
    print(f"Completed transactions: {transaction_count}")
    print("=============================")


if __name__ == "__main__":
    main()