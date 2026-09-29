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

    # The current test PCAP contains four
    # complete DNS query/response transactions.
    assert len(transactions) == 4

    transaction_ids = {
        transaction.transaction_id
        for transaction in transactions
    }

    assert transaction_ids == {
        100,
        101,
        102,
        103,
    }

    domains = {
        transaction.query_name
        for transaction in transactions
    }

    assert domains == {
        "example.com",
        "google.com",
        "openai.com",
        "www.github.com",
    }

    # Every transaction should have a response.
    assert all(
        transaction.response_received
        for transaction in transactions
    )