from dpi_engine.core.pcap_reader import PcapReader
from dpi_engine.core.packet_parser import PacketParser
from dpi_engine.dns.dns_flow_tracker import DNSFlowTracker


PCAP_PATH = "pcaps/test_traffic.pcap"


reader = PcapReader(PCAP_PATH)
parser = PacketParser()
dns_tracker = DNSFlowTracker()


for raw_packet in reader.packets():

    packet = parser.parse(raw_packet)

    if packet is None:
        continue

    transaction = dns_tracker.process_packet(packet)

    if transaction is None:
        continue

    print()
    print("========== DNS TRANSACTION ==========")

    print(
        "Transaction ID:",
        transaction.transaction_id
    )

    print(
        "Client:",
        f"{transaction.client_ip}:{transaction.client_port}"
    )

    print(
        "Server:",
        f"{transaction.server_ip}:{transaction.server_port}"
    )

    print(
        "Query Name:",
        transaction.query_name
    )

    print(
        "Query Type:",
        transaction.query_type
    )

    print(
        "Response Received:",
        transaction.response_received
    )

    print(
        "Response IPs:",
        transaction.response_ips
    )

    print(
        "Answer Record Types:",
        transaction.answer_record_types
    )

    print(
        "Response Time:",
        transaction.response_time
    )