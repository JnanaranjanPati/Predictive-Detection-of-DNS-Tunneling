from dataclasses import dataclass


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int


@dataclass(frozen=True)
class FiveTuple:
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    protocol: int

    @classmethod
    def from_packet(cls, packet):

        if not packet.src_ip or not packet.dst_ip:
            return None

        if packet.src_port is None or packet.dst_port is None:
            return None

        source = Endpoint(
            packet.src_ip,
            packet.src_port
        )

        destination = Endpoint(
            packet.dst_ip,
            packet.dst_port
        )

        if (source.ip, source.port) <= (
            destination.ip,
            destination.port
        ):
            a = source
            b = destination
        else:
            a = destination
            b = source

        return cls(
            endpoint_a=a,
            endpoint_b=b,
            protocol=packet.ip_protocol
        )