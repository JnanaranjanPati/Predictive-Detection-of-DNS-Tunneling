import json
from pathlib import Path

from .core.pcap_reader import PcapReader
from .core.packet_parser import PacketParser
from .flow.flow_tracker import FlowTracker
from .inspection.protocol_detector import ProtocolDetector


class DPIEngine:

    def __init__(self):

        self.parser = PacketParser()
        self.detector = ProtocolDetector()
        self.flow_tracker = FlowTracker()

        self.total_packets = 0
        self.protocol_counts = {}

    def process_pcap(self, filename):

        reader = PcapReader(filename)

        for raw_packet in reader.packets():

            self.total_packets += 1

            packet = self.parser.parse(
                raw_packet
            )

            protocol = self.detector.detect(
                packet
            )

            packet.application_protocol = protocol

            if protocol:
                self.protocol_counts[protocol] = (
                    self.protocol_counts.get(protocol, 0) + 1
                )

            self.flow_tracker.process(
                packet
            )

    def report(self):

        flows = []

        for flow in self.flow_tracker.get_flows():

            flows.append({
                "source": (
                    f"{flow.key.endpoint_a.ip}:"
                    f"{flow.key.endpoint_a.port}"
                ),
                "destination": (
                    f"{flow.key.endpoint_b.ip}:"
                    f"{flow.key.endpoint_b.port}"
                ),
                "ip_protocol": flow.key.protocol,
                "application_protocol": flow.application_protocol,
                "packets": flow.packets,
                "bytes": flow.bytes,
                "forward_packets": flow.forward_packets,
                "reverse_packets": flow.reverse_packets,
                "forward_bytes": flow.forward_bytes,
                "reverse_bytes": flow.reverse_bytes,
                "duration": flow.duration,
                "packets_per_second": flow.packets_per_second,
                "min_packet_length": flow.min_packet_length,
                "max_packet_length": flow.max_packet_length,
            })

        return {
            "total_packets": self.total_packets,
            "protocol_counts": self.protocol_counts,
            "total_flows": len(flows),
            "flows": flows,
        }

    def save_report(self, filename):

        path = Path(filename)

        path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with path.open(
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                self.report(),
                f,
                indent=2
            )