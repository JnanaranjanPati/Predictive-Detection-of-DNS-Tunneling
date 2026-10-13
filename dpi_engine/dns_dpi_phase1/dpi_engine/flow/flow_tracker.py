
from collections import OrderedDict
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
                packet_length,
            )

        self.max_packet_length = max(
            self.max_packet_length,
            packet_length,
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

    def __init__(
        self,
        idle_timeout=60.0,
        max_flows=10000,
    ):

        if idle_timeout <= 0:
            raise ValueError(
                "idle_timeout must be greater than 0"
            )

        if (
            not isinstance(max_flows, int)
            or isinstance(max_flows, bool)
            or max_flows <= 0
        ):
            raise ValueError(
                "max_flows must be a positive integer"
            )

        self.idle_timeout = float(idle_timeout)
        self.max_flows = max_flows

        # Ordered by recent activity, oldest flow first.
        self.flows = OrderedDict()

        self.expired_flow_count = 0
        self.evicted_flow_count = 0

    def expire_idle_flows(self, current_timestamp):
        """
        Remove flows idle for at least idle_timeout seconds.

        Returns the number of flows removed.
        """

        expired_keys = []

        for key, flow in self.flows.items():

            idle_duration = (
                current_timestamp - flow.last_timestamp
            )

            if idle_duration >= self.idle_timeout:
                expired_keys.append(key)

        for key in expired_keys:
            del self.flows[key]

        self.expired_flow_count += len(expired_keys)

        return len(expired_keys)

    def process(self, packet):

        # Expire stale flows before processing the new packet.
        self.expire_idle_flows(packet.timestamp)

        key = FiveTuple.from_packet(packet)

        if key is None:
            return None

        forward = (
            packet.src_ip == key.endpoint_a.ip
            and packet.src_port == key.endpoint_a.port
        )

        if key not in self.flows:

            # Evict the least recently active flow if at capacity.
            if len(self.flows) >= self.max_flows:
                self.flows.popitem(last=False)
                self.evicted_flow_count += 1

            self.flows[key] = Flow(
                key=key,
                first_timestamp=packet.timestamp,
                last_timestamp=packet.timestamp,
            )

        else:
            # Existing flow becomes the most recently active.
            self.flows.move_to_end(key)

        flow = self.flows[key]

        flow.update(
            packet,
            forward,
        )

        return flow

    def get_flows(self):
        return list(self.flows.values())
