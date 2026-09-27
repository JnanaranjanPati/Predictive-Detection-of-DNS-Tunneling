import struct

from .packet_types import ParsedPacket, RawPacket


class PacketParser:

    ETH_HEADER_LEN = 14

    ETHERTYPE_IPV4 = 0x0800

    IP_PROTO_ICMP = 1
    IP_PROTO_TCP = 6
    IP_PROTO_UDP = 17

    def parse(self, packet: RawPacket) -> ParsedPacket:

        data = packet.data

        result = ParsedPacket(
            timestamp=packet.timestamp,
            captured_length=packet.captured_length,
            original_length=packet.original_length,
        )

        if len(data) < self.ETH_HEADER_LEN:
            return result

        result.dst_mac = self._mac(data[0:6])
        result.src_mac = self._mac(data[6:12])

        result.ether_type = struct.unpack(
            "!H",
            data[12:14]
        )[0]

        if result.ether_type != self.ETHERTYPE_IPV4:
            return result

        ip_offset = self.ETH_HEADER_LEN

        if len(data) < ip_offset + 20:
            return result

        version_ihl = data[ip_offset]

        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4

        if version != 4:
            return result

        if len(data) < ip_offset + ihl:
            return result

        result.ttl = data[ip_offset + 8]
        result.ip_protocol = data[ip_offset + 9]

        result.src_ip = ".".join(
            str(x) for x in data[ip_offset + 12:ip_offset + 16]
        )

        result.dst_ip = ".".join(
            str(x) for x in data[ip_offset + 16:ip_offset + 20]
        )

        flags_fragment = struct.unpack(
            "!H",
            data[ip_offset + 6:ip_offset + 8]
        )[0]

        fragment_offset = flags_fragment & 0x1FFF

        more_fragments = bool(flags_fragment & 0x2000)

        if fragment_offset != 0 or more_fragments:
            result.fragmented = True
            return result

        transport_offset = ip_offset + ihl

        if result.ip_protocol == self.IP_PROTO_TCP:
            self._parse_tcp(data, transport_offset, result)

        elif result.ip_protocol == self.IP_PROTO_UDP:
            self._parse_udp(data, transport_offset, result)

        return result

    def _parse_tcp(self, data, offset, result):

        if len(data) < offset + 20:
            return

        result.src_port, result.dst_port = struct.unpack(
            "!HH",
            data[offset:offset + 4]
        )

        result.tcp_seq = struct.unpack(
            "!I",
            data[offset + 4:offset + 8]
        )[0]

        result.tcp_ack = struct.unpack(
            "!I",
            data[offset + 8:offset + 12]
        )[0]

        data_offset = (data[offset + 12] >> 4) * 4

        result.tcp_flags = data[offset + 13]

        payload_offset = offset + data_offset

        if payload_offset < len(data):
            result.payload = data[payload_offset:]

    def _parse_udp(self, data, offset, result):

        if len(data) < offset + 8:
            return

        result.src_port, result.dst_port = struct.unpack(
            "!HH",
            data[offset:offset + 4]
        )

        payload_offset = offset + 8

        if payload_offset < len(data):
            result.payload = data[payload_offset:]

    @staticmethod
    def _mac(data):

        return ":".join(
            f"{byte:02x}" for byte in data
        )