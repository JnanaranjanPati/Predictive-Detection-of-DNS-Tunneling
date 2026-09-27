from dataclasses import dataclass

from .five_tuple import FiveTuple


@dataclass
class Flow:

    key: FiveTuple

    first_timestamp: float
    last_timestamp: float

    packets: int = 0
    bytes: int = 0

    forward_packets: int = 0
    reverse_packets: int = 0

    forward_bytes: int = 0
    reverse_bytes: int = 0

    min_packet_length: int = 0
    max_packet_length: int = 0

    application_protocol: str = "UNKNOWN"

    def update(self, packet, forward):

        packet_length = packet.original_length

        self.packets += 1
        self.bytes += packet_length

        self.last_timestamp = packet.timestamp

        if forward:
            self.forward_packets += 1
            self.forward_bytes += packet_length
        else:
            self.reverse_packets += 1
            self.reverse_bytes += packet_length

        if self.min_packet_length == 0:
            self.min_packet_length = packet_length
        else:
            self.min_packet_length = min(
                self.min_packet_length,
                packet_length
            )

        self.max_packet_length = max(
            self.max_packet_length,
            packet_length
        )

        if packet.application_protocol:
            self.application_protocol = packet.application_protocol

    @property
    def duration(self):

        return self.last_timestamp - self.first_timestamp

    @property
    def packets_per_second(self):

        if self.duration <= 0:
            return float(self.packets)

        return self.packets / self.duration


class FlowTracker:

    def __init__(self):

        self.flows = {}

    def process(self, packet):

        key = FiveTuple.from_packet(packet)

        if key is None:
            return None

        forward = (
            packet.src_ip == key.endpoint_a.ip
            and packet.src_port == key.endpoint_a.port
        )

        if key not in self.flows:

            self.flows[key] = Flow(
                key=key,
                first_timestamp=packet.timestamp,
                last_timestamp=packet.timestamp,
            )

        flow = self.flows[key]

        flow.update(
            packet,
            forward
        )

        return flow

    def get_flows(self):

        return list(self.flows.values())