from dpi_engine.core.pcap_reader import PcapReader
from dpi_engine.core.packet_parser import PacketParser
from dpi_engine.dns.dns_parser import DNSParser


def test_dns_parser():

    reader = PcapReader(
        "pcaps/test_traffic.pcap"
    )

    packet_parser = PacketParser()
    dns_parser = DNSParser()

    dns_packets = []

    for raw_packet in reader.packets():

        packet = packet_parser.parse(raw_packet)

        if (
            packet.src_port == 53
            or packet.dst_port == 53
        ):
            dns_packets.append(packet)

    assert len(dns_packets) == 2

    query = dns_parser.parse(
        dns_packets[0].payload
    )

    response = dns_parser.parse(
        dns_packets[1].payload
    )

    assert query is not None
    assert response is not None

    assert query["transaction_id"] == 100
    assert response["transaction_id"] == 100

    assert query["is_response"] is False
    assert response["is_response"] is True

    assert query["query_name"] == "example.com"
    assert response["query_name"] == "example.com"

    assert query["query_type"] == "A"