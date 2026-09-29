from scapy.all import sniff

from .core.packet_types import RawPacket


class LiveCapture:
    """
    Captures live packets using Scapy/Npcap and converts them
    into the project's existing RawPacket format.
    """

    def __init__(self, interface=None):
        self.interface = interface

    def _to_raw_packet(self, packet):
        """
        Convert a Scapy packet into the project's RawPacket structure.
        """
        data = bytes(packet)

        return RawPacket(
            timestamp=float(packet.time),
            captured_length=len(data),
            original_length=len(data),
            data=data,
        )

    def capture(self, count=0, timeout=None, packet_filter=None):
        """
        Capture live packets.

        Parameters:
            count: Number of packets to capture. 0 = unlimited.
            timeout: Capture timeout in seconds.
            packet_filter: Optional BPF filter such as 'udp port 53'.

        Returns:
            List of RawPacket objects.
        """

        packets = sniff(
            iface=self.interface,
            count=count,
            timeout=timeout,
            filter=packet_filter,
        )

        return [self._to_raw_packet(packet) for packet in packets]