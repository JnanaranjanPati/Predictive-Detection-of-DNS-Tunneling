
from dpi_engine.core.pcap_reader import PcapReader
from dpi_engine.core.packet_parser import PacketParser
from dpi_engine.dns.dns_flow_tracker import DNSFlowTracker


def test_completed_transaction_history_stays_bounded_under_load():
    reader = PcapReader("pcaps/test_traffic.pcap")
    raw_packets = list(reader.packets())
    parser = PacketParser()

    tracker = DNSFlowTracker(
        max_history=10_000,
        max_flow_history=1_000,
        max_tracked_flows=1_000,
    )

    target_completions = 12_000
    repetitions = target_completions // 4

    for _ in range(repetitions):
        for raw_packet in raw_packets:
            packet = parser.parse(raw_packet)
            tracker.process_packet(packet)

    assert tracker.total_transactions_completed == target_completions
    assert len(tracker.get_transactions()) == 10_000
    assert len(tracker.pending_transactions) == 0

    retained_ids = [
        transaction.transaction_id
        for transaction in tracker.get_transactions()
    ]

    # The most recent 10,000 transactions should be retained.
    assert len(retained_ids) == 10_000
    assert retained_ids[-4:] == [100, 101, 102, 103]
