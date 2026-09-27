from dpi_engine.core.pcap_reader import PcapReader


def test_pcap_reader():

    reader = PcapReader(
        "pcaps/test_traffic.pcap"
    )

    packets = list(
        reader.packets()
    )

    assert len(packets) == 8

    assert packets[0].captured_length > 0