from dpi_engine.core.pcap_reader import PcapReader


def test_pcap_reader():

    reader = PcapReader(
        "pcaps/test_traffic.pcap"
    )

    packets = list(
        reader.packets()
    )

    assert len(packets) == 14

    # Verify timestamps are present and ordered.
    assert packets[0].timestamp < packets[-1].timestamp

    # Verify packet lengths are valid.
    assert all(
        packet.captured_length > 0
        for packet in packets
    )