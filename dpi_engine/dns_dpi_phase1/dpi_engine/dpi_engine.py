
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

    def __init__(self, max_detections=10000):

        if (
            not isinstance(max_detections, int)
            or isinstance(max_detections, bool)
            or max_detections <= 0
        ):
            raise ValueError(
                "max_detections must be a positive integer"
            )

        # =========================================================
        # DPI COMPONENTS
        # =========================================================

        self.parser = PacketParser()
        self.detector = ProtocolDetector()
        self.flow_tracker = FlowTracker()

        # =========================================================
        # DNS INSPECTION AND ML COMPONENTS
        # =========================================================

        self.dns_flow_tracker = DNSFlowTracker()
        self.dns_ml_pipeline = DNSMLPipeline()

        # =========================================================
        # PACKET STATISTICS
        # =========================================================

        self.total_packets = 0
        self.protocol_counts = {}

        # =========================================================
        # BOUNDED DNS DETECTION HISTORY
        # =========================================================

        self.max_detections = max_detections
        self.dns_detections = []

        # Lifetime counters remain accurate even after old
        # detection records are removed from retained history.
        self.total_dns_predictions = 0
        self.total_benign_predictions = 0
        self.total_malicious_predictions = 0

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
        report_filename="reports/live_dns_detection_report.json",
    ):
        """
        Capture and process live packets using Scapy/Npcap.

        Parameters:
            interface:
                Windows Npcap interface. If None, Scapy uses
                its default interface.

            count:
                Number of packets to capture.
                0 means unlimited until timeout or interruption.

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
        printed_predictions = self.total_dns_predictions

        def packet_callback(scapy_packet):

            nonlocal captured_count
            nonlocal printed_predictions

            # Convert Scapy packet to the project's RawPacket.
            raw_packet = self._scapy_to_raw_packet(
                scapy_packet
            )

            # Process through the existing DPI pipeline.
            self._process_raw_packet(raw_packet)

            captured_count += 1

            # Print newly generated predictions.
            # Use lifetime counters instead of retained list length,
            # because old detections may be trimmed.
            if self.total_dns_predictions > printed_predictions:

                latest_detection = self.dns_detections[-1]

                self._print_live_detection(
                    latest_detection
                )

                printed_predictions = self.total_dns_predictions

        interrupted = False

        try:
            sniff(
                iface=interface,
                count=count,
                timeout=timeout,
                filter=packet_filter,
                prn=packet_callback,
                store=False,
            )

        except KeyboardInterrupt:
            interrupted = True
            print("\nLive capture interrupted by user.")

        finally:
            self._print_live_summary(captured_count)
        if report_filename:
            try:
                self.save_report(report_filename)
                print(f"Final report saved to: {report_filename}")
            except OSError as error:
                print(f"Could not save final report: {error}")

        if interrupted:
            print("Capture stopped cleanly.")

    def _print_live_summary(self, captured_count):

        print()
        print("========== LIVE CAPTURE SUMMARY ==========")

        print(f"Captured packets: {captured_count}")
        print(f"Processed packets: {self.total_packets}")

        print(
            f"Total DNS predictions: "
            f"{self.total_dns_predictions}"
        )

        print(
            f"Benign predictions: "
            f"{self.total_benign_predictions}"
        )

        print(
            f"Malicious predictions: "
            f"{self.total_malicious_predictions}"
        )

        print(
            f"Retained detections: "
            f"{len(self.dns_detections)}"
        )

        print(
            f"Expired pending DNS transactions: "
            f"{self.dns_flow_tracker.expired_transaction_count}"
        )

        print(
            f"Expired generic flows: "
            f"{self.flow_tracker.expired_flow_count}"
        )

        print(
            f"Evicted generic flows: "
            f"{self.flow_tracker.evicted_flow_count}"
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

        packet = self.parser.parse(raw_packet)

        if packet is None:
            return

        # ---------------------------------------------------------
        # Generic protocol detection
        # ---------------------------------------------------------

        protocol = self.detector.detect(packet)

        packet.application_protocol = protocol

        if protocol:
            self.protocol_counts[protocol] = (
                self.protocol_counts.get(protocol, 0) + 1
            )

        # ---------------------------------------------------------
        # Generic flow tracking
        # ---------------------------------------------------------

        self.flow_tracker.process(packet)

        # ---------------------------------------------------------
        # DNS flow tracking
        # ---------------------------------------------------------

        transaction = self.dns_flow_tracker.process_packet(
            packet
        )

        # ---------------------------------------------------------
        # DNS ML inference
        # ---------------------------------------------------------

        if (
            transaction is not None
            and transaction.response_received
        ):

            prediction = self.dns_ml_pipeline.predict_transaction(
                transaction
            )

            # Add transaction metadata to the prediction.
            prediction["transaction_id"] = (
                transaction.transaction_id
            )

            prediction["query_name"] = transaction.query_name
            prediction["client_ip"] = transaction.client_ip
            prediction["client_port"] = transaction.client_port
            prediction["server_ip"] = transaction.server_ip
            prediction["server_port"] = transaction.server_port
            prediction["response_time"] = transaction.response_time

            # Update lifetime counters before trimming history.
            self.total_dns_predictions += 1

            if prediction["prediction"] == 0:
                self.total_benign_predictions += 1

            elif prediction["prediction"] == 1:
                self.total_malicious_predictions += 1

            # Retain only the most recent detection records.
            self.dns_detections.append(prediction)

            if len(self.dns_detections) > self.max_detections:
                del self.dns_detections[
                    :-self.max_detections
                ]

    # =============================================================
    # SCAPY TO RAW PACKET ADAPTER
    # =============================================================

    @staticmethod
    def _scapy_to_raw_packet(scapy_packet):
        """
        Convert a Scapy packet into the project's RawPacket structure.
        """

        data = bytes(scapy_packet)

        return RawPacket(
            timestamp=float(scapy_packet.time),
            captured_length=len(data),
            original_length=len(data),
            data=data,
        )

    # =============================================================
    # LIVE DETECTION OUTPUT
    # =============================================================

    @staticmethod
    def _print_live_detection(detection):

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

        # ---------------------------------------------------------
        # Generic flow report
        # ---------------------------------------------------------

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

                "forward_packets": flow.forward_packets,
                "reverse_packets": flow.reverse_packets,

                "forward_bytes": flow.forward_bytes,
                "reverse_bytes": flow.reverse_bytes,

                "duration": flow.duration,

                "packets_per_second": (
                    flow.packets_per_second
                ),

                "min_packet_length": flow.min_packet_length,
                "max_packet_length": flow.max_packet_length,
            })

        # ---------------------------------------------------------
        # Complete report
        # ---------------------------------------------------------

        return {
            "total_packets": self.total_packets,

            "protocol_counts": self.protocol_counts,

            "total_flows": len(flows),

            "flows": flows,

            "dns_ml": {
                # Lifetime prediction count.
                "total_transactions": self.total_dns_predictions,

                # Number of records still retained in memory.
                "retained_detection_count": len(
                    self.dns_detections
                ),

                # Lifetime class counts.
                "benign_transactions": (
                    self.total_benign_predictions
                ),

                "malicious_transactions": (
                    self.total_malicious_predictions
                ),

                # Recent retained detections.
                "detections": self.dns_detections,
            },
        }

    # =============================================================
    # SAVE REPORT
    # =============================================================

    def save_report(self, filename):

        path = Path(filename)

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with path.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.report(),
                file,
                indent=2,
            )


    


