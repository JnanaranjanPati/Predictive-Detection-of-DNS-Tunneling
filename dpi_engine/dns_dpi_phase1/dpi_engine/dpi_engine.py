import json
from pathlib import Path

from scapy.all import sniff

from .core.pcap_reader import PcapReader
from .core.packet_types import RawPacket
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

    # =============================================================
    # PCAP PROCESSING
    # =============================================================

    def process_pcap(self, filename):

        reader = PcapReader(filename)

        for raw_packet in reader.packets():

            self._process_raw_packet(raw_packet)

    # =============================================================
    # LIVE PACKET PROCESSING
    # =============================================================

    def process_live(
        self,
        interface=None,
        count=0,
        timeout=None,
        packet_filter="udp port 53",
    ):
        """
        Capture and process live packets using Scapy/Npcap.

        Parameters:
            interface:
                Windows Npcap interface. If None, Scapy uses
                its default interface.

            count:
                Number of packets to capture.
                0 means unlimited until timeout/stop.

            timeout:
                Capture timeout in seconds.
                None means no timeout.

            packet_filter:
                BPF filter. Default captures DNS over UDP/53.
        """

        print("Starting live DPI capture...")
        print(f"Interface: {interface or 'Scapy default'}")
        print(f"Filter: {packet_filter or 'None'}")

        captured_count = 0
        printed_detections = 0

        def packet_callback(scapy_packet):

            nonlocal captured_count
            nonlocal printed_detections

            # -----------------------------------------------------
            # Convert Scapy packet to project RawPacket
            # -----------------------------------------------------

            raw_packet = self._scapy_to_raw_packet(
                scapy_packet
            )

            # -----------------------------------------------------
            # Process through the existing DPI pipeline
            # -----------------------------------------------------

            self._process_raw_packet(
                raw_packet
            )

            captured_count += 1

            # -----------------------------------------------------
            # Print only newly generated DNS ML detections
            # -----------------------------------------------------

            if len(self.dns_detections) > printed_detections:

                latest_detection = (
                    self.dns_detections[-1]
                )

                self._print_live_detection(
                    latest_detection
                )

                printed_detections = (
                    len(self.dns_detections)
                )

        sniff(
            iface=interface,
            count=count,
            timeout=timeout,
            filter=packet_filter,
            prn=packet_callback,
            store=False,
        )

        # =========================================================
        # LIVE CAPTURE SUMMARY
        # =========================================================

        print()
        print("========== LIVE CAPTURE SUMMARY ==========")
        print(
            f"Captured packets: "
            f"{captured_count}"
        )

        print(
            f"Processed packets: "
            f"{self.total_packets}"
        )

        print(
            "DNS transactions: "
            f"{len(self.dns_detections)}"
        )

        benign_count = sum(
            1
            for detection in self.dns_detections
            if detection["prediction"] == 0
        )

        malicious_count = sum(
            1
            for detection in self.dns_detections
            if detection["prediction"] == 1
        )

        print(
            f"Benign: "
            f"{benign_count}"
        )

        print(
            f"Malicious: "
            f"{malicious_count}"
        )

        print("==========================================")

    # =============================================================
    # COMMON PACKET PROCESSING
    # =============================================================

    def _process_raw_packet(self, raw_packet):

        self.total_packets += 1

        # ---------------------------------------------------------
        # Parse packet
        # ---------------------------------------------------------

        packet = self.parser.parse(
            raw_packet
        )

        if packet is None:
            return

        # ---------------------------------------------------------
        # Generic protocol detection
        # ---------------------------------------------------------

        protocol = self.detector.detect(
            packet
        )

        packet.application_protocol = protocol

        if protocol:

            self.protocol_counts[protocol] = (
                self.protocol_counts.get(
                    protocol,
                    0
                ) + 1
            )

        # ---------------------------------------------------------
        # Existing generic flow tracking
        # ---------------------------------------------------------

        self.flow_tracker.process(
            packet
        )

        # ---------------------------------------------------------
        # DNS flow tracking
        # ---------------------------------------------------------

        transaction = (
            self.dns_flow_tracker.process_packet(
                packet
            )
        )

        # ---------------------------------------------------------
        # DNS ML inference
        # ---------------------------------------------------------

        if (
            transaction is not None
            and transaction.response_received
        ):

            prediction = (
                self.dns_ml_pipeline.predict_transaction(
                    transaction
                )
            )

            # -----------------------------------------------------
            # Store transaction metadata with prediction
            # -----------------------------------------------------

            prediction["transaction_id"] = (
                transaction.transaction_id
            )

            prediction["query_name"] = (
                transaction.query_name
            )

            prediction["client_ip"] = (
                transaction.client_ip
            )

            prediction["client_port"] = (
                transaction.client_port
            )

            prediction["server_ip"] = (
                transaction.server_ip
            )

            prediction["server_port"] = (
                transaction.server_port
            )

            prediction["response_time"] = (
                transaction.response_time
            )

            self.dns_detections.append(
                prediction
            )

    # =============================================================
    # SCAPY → RAW PACKET ADAPTER
    # =============================================================

    @staticmethod
    def _scapy_to_raw_packet(
        scapy_packet
    ):
        """
        Convert a Scapy packet into the project's
        existing RawPacket structure.
        """

        data = bytes(
            scapy_packet
        )

        return RawPacket(
            timestamp=float(
                scapy_packet.time
            ),
            captured_length=len(data),
            original_length=len(data),
            data=data,
        )

    # =============================================================
    # LIVE DETECTION OUTPUT
    # =============================================================

    @staticmethod
    def _print_live_detection(
        detection
    ):

        print()
        print("========== DNS ML DETECTION ==========")

        print(
            f"Transaction ID: "
            f"{detection.get('transaction_id')}"
        )

        print(
            f"Query: "
            f"{detection.get('query_name')}"
        )

        print(
            f"Prediction: "
            f"{detection.get('label')}"
        )

        print(
            "Malicious probability: "
            f"{detection.get('malicious_probability', 0.0):.4f}"
        )

        print(
            f"Response time: "
            f"{detection.get('response_time')}"
        )

        print("======================================")

    # =============================================================
    # REPORT
    # =============================================================

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

    # =============================================================
    # SAVE REPORT
    # =============================================================

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