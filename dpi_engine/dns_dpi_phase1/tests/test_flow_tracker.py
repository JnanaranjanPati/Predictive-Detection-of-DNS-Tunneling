from dpi_engine.core.pcap_reader import PcapReader
from dpi_engine.core.packet_parser import PacketParser
from dpi_engine.flow.flow_tracker import FlowTracker


def test_bidirectional_flow():

    reader = PcapReader(
        "pcaps/test_traffic.pcap"
    )

    parser = PacketParser()
    tracker = FlowTracker()

    for raw_packet in reader.packets():

        packet = parser.parse(
            raw_packet
        )

        tracker.process(
            packet
        )

    flows = tracker.get_flows()

    assert len(flows) == 4

    dns_flows = [
        flow
        for flow in flows
        if flow.key.endpoint_a.port == 53
        or flow.key.endpoint_b.port == 53
    ]

    assert len(dns_flows) == 1

    assert dns_flows[0].packets == 2