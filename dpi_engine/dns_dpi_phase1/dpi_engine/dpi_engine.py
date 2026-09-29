import json
from pathlib import Path

from .core.pcap_reader import PcapReader
from .core.packet_parser import PacketParser
from .flow.flow_tracker import FlowTracker
from .inspection.protocol_detector import ProtocolDetector
from .dns.dns_flow_tracker import DNSFlowTracker
from .dns.dns_ml_pipeline import DNSMLPipeline


class DPIEngine:

    def __init__(self):

        # =========================================================
        # Existing DPI components
        # =========================================================

        self.parser = PacketParser()
        self.detector = ProtocolDetector()
        self.flow_tracker = FlowTracker()

        # =========================================================
        # DNS inspection + ML components
        # =========================================================

        self.dns_flow_tracker = DNSFlowTracker()
        self.dns_ml_pipeline = DNSMLPipeline()

        # =========================================================
        # Existing statistics
        # =========================================================

        self.total_packets = 0
        self.protocol_counts = {}

        # =========================================================
        # DNS ML detections
        # =========================================================

        self.dns_detections = []

    def process_pcap(self, filename):

        reader = PcapReader(filename)

        for raw_packet in reader.packets():

            self.total_packets += 1

            # -----------------------------------------------------
            # Parse packet
            # -----------------------------------------------------

            packet = self.parser.parse(
                raw_packet
            )

            # -----------------------------------------------------
            # Generic protocol detection
            # -----------------------------------------------------

            protocol = self.detector.detect(
                packet
            )

            packet.application_protocol = protocol

            if protocol:

                self.protocol_counts[protocol] = (
                    self.protocol_counts.get(protocol, 0) + 1
                )

            # -----------------------------------------------------
            # Existing generic flow tracking
            # -----------------------------------------------------

            self.flow_tracker.process(
                packet
            )

            # -----------------------------------------------------
            # DNS flow tracking
            # -----------------------------------------------------

            transaction = self.dns_flow_tracker.process_packet(
                packet
            )

            # -----------------------------------------------------
            # DNS ML inference
            # -----------------------------------------------------
            #
            # DNSFlowTracker returns:
            #
            #   - query transaction when query arrives
            #   - completed transaction when response arrives
            #
            # Only run ML inference for completed transactions.
            # -----------------------------------------------------

            if (
                transaction is not None
                and transaction.response_received
            ):

                prediction = (
                    self.dns_ml_pipeline.predict_transaction(
                        transaction
                    )
                )

                self.dns_detections.append(
                    prediction
                )

    def report(self):

        # =========================================================
        # Existing generic flow report
        # =========================================================

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

                "application_protocol": (
                    flow.application_protocol
                ),

                "packets": flow.packets,

                "bytes": flow.bytes,

                "forward_packets": (
                    flow.forward_packets
                ),

                "reverse_packets": (
                    flow.reverse_packets
                ),

                "forward_bytes": (
                    flow.forward_bytes
                ),

                "reverse_bytes": (
                    flow.reverse_bytes
                ),

                "duration": flow.duration,

                "packets_per_second": (
                    flow.packets_per_second
                ),

                "min_packet_length": (
                    flow.min_packet_length
                ),

                "max_packet_length": (
                    flow.max_packet_length
                ),
            })

        # =========================================================
        # DNS ML summary
        # =========================================================

        malicious_count = sum(
            1
            for detection in self.dns_detections
            if detection["prediction"] == 1
        )

        benign_count = sum(
            1
            for detection in self.dns_detections
            if detection["prediction"] == 0
        )

        # =========================================================
        # Complete report
        # =========================================================

        return {

            # -----------------------------------------------------
            # Generic DPI information
            # -----------------------------------------------------

            "total_packets": self.total_packets,

            "protocol_counts": self.protocol_counts,

            "total_flows": len(flows),

            "flows": flows,

            # -----------------------------------------------------
            # DNS ML information
            # -----------------------------------------------------

            "dns_ml": {

                "total_transactions": (
                    len(self.dns_detections)
                ),

                "benign_transactions": (
                    benign_count
                ),

                "malicious_transactions": (
                    malicious_count
                ),

                "detections": (
                    self.dns_detections
                ),
            },
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