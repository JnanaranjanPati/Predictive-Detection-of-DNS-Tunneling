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

        packet = packet_parser.parse(
            raw_packet
        )

        if (
            packet.src_port == 53
            or packet.dst_port == 53
        ):
            dns_packets.append(packet)

    # Four DNS transactions = eight DNS packets.
    assert len(dns_packets) == 8

    parsed_queries = []

    for packet in dns_packets:

        parsed = dns_parser.parse(
            packet.payload
        )

        assert parsed is not None

        parsed_queries.append(parsed)

    # Four DNS queries and four responses.
    query_count = sum(
        1
        for parsed in parsed_queries
        if not parsed["is_response"]
    )

    response_count = sum(
        1
        for parsed in parsed_queries
        if parsed["is_response"]
    )

    assert query_count == 4
    assert response_count == 4