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

    # Current test PCAP:
    #
    # 4 DNS flows
    # 1 HTTP flow
    # 1 HTTPS/TLS flow
    # 1 SSH flow
    #
    # Total = 7 flows.
    assert len(flows) == 7

    # Every flow should contain packets in both directions.
    for flow in flows:

        assert flow.forward_packets > 0
        assert flow.reverse_packets > 0

        assert flow.packets == (
            flow.forward_packets
            + flow.reverse_packets
        )

        assert flow.bytes == (
            flow.forward_bytes
            + flow.reverse_bytes
        )