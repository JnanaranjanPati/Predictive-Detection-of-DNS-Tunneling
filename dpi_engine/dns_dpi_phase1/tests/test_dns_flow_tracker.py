from dpi_engine.core.pcap_reader import PcapReader
from dpi_engine.core.packet_parser import PacketParser
from dpi_engine.dns.dns_flow_tracker import DNSFlowTracker


def test_dns_transaction_tracking():

    reader = PcapReader(
        "pcaps/test_traffic.pcap"
    )

    parser = PacketParser()

    tracker = DNSFlowTracker()

    for raw_packet in reader.packets():

        packet = parser.parse(
            raw_packet
        )

        tracker.process_packet(
            packet
        )

    transactions = (
        tracker.get_transactions()
    )

    assert len(transactions) == 1

    transaction = transactions[0]

    assert transaction.transaction_id == 100

    assert transaction.client_ip == (
        "192.168.1.10"
    )

    assert transaction.server_ip == (
        "8.8.8.8"
    )

    assert transaction.query_name == (
        "example.com"
    )

    assert transaction.query_type == "A"

    assert transaction.response_received is True

    assert transaction.response_time is not None

    assert transaction.response_time >= 0

    assert transaction.response_ips == [
        "93.184.216.34"
    ]