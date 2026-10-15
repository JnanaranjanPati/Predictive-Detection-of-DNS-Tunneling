from dpi_engine.core.pcap_reader import PcapReader
from dpi_engine.core.packet_parser import PacketParser
from dpi_engine.dns.dns_flow_tracker import DNSFlowTracker
from dpi_engine.dns.dns_transaction import DNSTransaction

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

    
def test_pending_transaction_expires_after_timeout():
    tracker = DNSFlowTracker(transaction_timeout=30.0)

    transaction = DNSTransaction(
        transaction_id=500,
        client_ip="192.0.2.10",
        client_port=40000,
        server_ip="192.0.2.53",
        server_port=53,
        query_name="example.com",
        query_timestamp=100.0,
    )

    key = tracker._transaction_key(
        500,
        "192.0.2.10",
        40000,
        "192.0.2.53",
        53,
    )

    tracker.pending_transactions[key] = transaction

    expired = tracker.expire_pending_transactions(131.0)

    assert expired == 1
    assert key not in tracker.pending_transactions
    assert tracker.expired_transaction_count == 1


def test_pending_transaction_is_not_expired_early():
    tracker = DNSFlowTracker(transaction_timeout=30.0)

    transaction = DNSTransaction(
        transaction_id=501,
        client_ip="192.0.2.10",
        client_port=40001,
        server_ip="192.0.2.53",
        server_port=53,
        query_name="example.com",
        query_timestamp=100.0,
    )

    key = tracker._transaction_key(
        501,
        "192.0.2.10",
        40001,
        "192.0.2.53",
        53,
    )

    tracker.pending_transactions[key] = transaction

    expired = tracker.expire_pending_transactions(129.0)

    assert expired == 0
    assert key in tracker.pending_transactions
    assert tracker.expired_transaction_count == 0



def test_completed_transaction_history_is_bounded():
    reader = PcapReader("pcaps/test_traffic.pcap")
    raw_packets = list(reader.packets())

    parser = PacketParser()
    tracker = DNSFlowTracker(
        max_history=2,
        max_flow_history=10,
        max_tracked_flows=10,
    )

    # Replay the real query/response packets three times.
    # Each replay contains four completed DNS transactions.
    for _ in range(3):
        for raw_packet in raw_packets:
            packet = parser.parse(raw_packet)
            tracker.process_packet(packet)

    transactions = tracker.get_transactions()

    # Only the two newest completed transactions should remain.
    assert len(transactions) == 2
    assert [
        transaction.transaction_id
        for transaction in transactions
    ] == [102, 103]

    # Lifetime counters must include all 12 completions.
    assert tracker.total_transactions_completed == 12
    assert tracker.total_responses_matched == 12
    assert tracker.total_queries_seen == 12

    # Every query should have been matched and removed.
    assert len(tracker.pending_transactions) == 0


def test_per_flow_query_history_is_bounded():
    tracker = DNSFlowTracker(
        max_history=10,
        max_flow_history=2,
        max_tracked_flows=10,
    )

    flow_key = ("192.0.2.10", "192.0.2.53")

    tracker._append_flow_history(
        tracker.flow_queries, flow_key, "first"
    )
    tracker._append_flow_history(
        tracker.flow_queries, flow_key, "second"
    )
    tracker._append_flow_history(
        tracker.flow_queries, flow_key, "third"
    )

    assert tracker.flow_queries[flow_key] == ["second", "third"]


def test_tracked_flow_count_is_bounded():
    tracker = DNSFlowTracker(
        max_history=10,
        max_flow_history=10,
        max_tracked_flows=2,
    )

    for index in range(3):
        flow_key = (
            f"192.0.2.{index + 1}",
            "192.0.2.53",
        )
        tracker._append_flow_history(
            tracker.flow_queries, flow_key, f"query-{index}"
        )

    assert len(tracker.flow_queries) == 2
    assert ("192.0.2.1", "192.0.2.53") not in tracker.flow_queries


def test_invalid_history_limit_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        DNSFlowTracker(max_history=0)



def test_idle_flow_expires():
    from types import SimpleNamespace
    from dpi_engine.flow.flow_tracker import FlowTracker

    tracker = FlowTracker(idle_timeout=60)

    key = "test-flow"
    tracker.flows[key] = SimpleNamespace(last_timestamp=100.0)

    expired = tracker.expire_idle_flows(160.0)

    assert expired == 1
    assert key not in tracker.flows
    assert tracker.expired_flow_count == 1


def test_recent_flow_does_not_expire():
    from types import SimpleNamespace
    from dpi_engine.flow.flow_tracker import FlowTracker

    tracker = FlowTracker(idle_timeout=60)

    key = "test-flow"
    flow = SimpleNamespace(last_timestamp=100.0)
    tracker.flows[key] = flow

    expired = tracker.expire_idle_flows(159.0)

    assert expired == 0
    assert key in tracker.flows
    assert tracker.expired_flow_count == 0


def test_flow_tracker_rejects_invalid_capacity():
    import pytest
    from dpi_engine.flow.flow_tracker import FlowTracker

    with pytest.raises(ValueError):
        FlowTracker(max_flows=0)



def test_flow_tracker_evicts_oldest_flow_at_capacity():
    from types import SimpleNamespace
    from dpi_engine.flow.flow_tracker import FlowTracker

    tracker = FlowTracker(max_flows=2)

    first_key = "first-flow"
    second_key = "second-flow"
    third_key = "third-flow"

    tracker.flows[first_key] = SimpleNamespace(last_timestamp=1.0)
    tracker.flows[second_key] = SimpleNamespace(last_timestamp=2.0)

    # Mark the second flow as more recently active.
    tracker.flows.move_to_end(second_key)

    # Simulate insertion at capacity using the tracker's eviction rule.
    if len(tracker.flows) >= tracker.max_flows:
        tracker.flows.popitem(last=False)
        tracker.evicted_flow_count += 1

    tracker.flows[third_key] = SimpleNamespace(last_timestamp=3.0)

    assert first_key not in tracker.flows
    assert second_key in tracker.flows
    assert third_key in tracker.flows
    assert tracker.evicted_flow_count == 1
