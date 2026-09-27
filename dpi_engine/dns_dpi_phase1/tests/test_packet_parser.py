from dpi_engine.core.pcap_reader import PcapReader
from dpi_engine.core.packet_parser import PacketParser


def test_packet_parser():

    reader = PcapReader(
        "pcaps/test_traffic.pcap"
    )

    parser = PacketParser()

    packets = list(
        reader.packets()
    )

    parsed = [
        parser.parse(packet)
        for packet in packets
    ]

    assert parsed[0].src_ip == "192.168.1.10"
    assert parsed[0].dst_ip == "8.8.8.8"

    assert parsed[0].src_port == 53000
    assert parsed[0].dst_port == 53