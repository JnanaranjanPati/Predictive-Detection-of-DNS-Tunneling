from dpi_engine.core.pcap_reader import PcapReader
from dpi_engine.core.packet_parser import PacketParser
from dpi_engine.dns.dns_flow_tracker import DNSFlowTracker
from dpi_engine.dns.dns_feature_extractor import (
    FEATURE_ORDER,
    build_feature_vector,
)


PCAP_PATH = "pcaps/test_traffic.pcap"


reader = PcapReader(PCAP_PATH)
parser = PacketParser()
dns_tracker = DNSFlowTracker()


for raw_packet in reader.packets():

    packet = parser.parse(raw_packet)

    if packet is None:
        continue

    transaction = dns_tracker.process_packet(packet)

    if transaction is None:
        continue

    # We only build features after the DNS response
    # has been received.
    if not transaction.response_received:
        continue

    # ---------------------------------------------------------
    # Collect packet lengths for this DNS transaction
    # ---------------------------------------------------------
    #
    # The current test transaction consists of the DNS query
    # and DNS response packets.
    #
    # We collect their packet lengths from the PCAP.
    #
    # For this first validation, the transaction is identified
    # by its client/server IP and ports.

    packet_lengths = []

    for raw_packet_2 in PcapReader(PCAP_PATH).packets():

        packet_2 = parser.parse(raw_packet_2)

        if packet_2 is None:
            continue

        same_flow = (
            (
                packet_2.src_ip == transaction.client_ip
                and
                packet_2.src_port == transaction.client_port
                and
                packet_2.dst_ip == transaction.server_ip
                and
                packet_2.dst_port == transaction.server_port
            )
            or
            (
                packet_2.src_ip == transaction.server_ip
                and
                packet_2.src_port == transaction.server_port
                and
                packet_2.dst_ip == transaction.client_ip
                and
                packet_2.dst_port == transaction.client_port
            )
        )

        if same_flow:
            packet_lengths.append(
                packet_2.packet_length
            )

    # ---------------------------------------------------------
    # Calculate duration
    # ---------------------------------------------------------

    duration = transaction.response_time

    if duration is None:
        duration = 0.0

    # ---------------------------------------------------------
    # Calculate sending bytes
    # ---------------------------------------------------------
    #
    # Sending bytes means bytes sent by the DNS client.
    #
    # We therefore only sum packets in the
    # client -> server direction.
    # ---------------------------------------------------------

    sending_bytes = 0

    for raw_packet_3 in PcapReader(PCAP_PATH).packets():

        packet_3 = parser.parse(raw_packet_3)

        if packet_3 is None:
            continue

        is_client_to_server = (
            packet_3.src_ip == transaction.client_ip
            and
            packet_3.src_port == transaction.client_port
            and
            packet_3.dst_ip == transaction.server_ip
            and
            packet_3.dst_port == transaction.server_port
        )

        if is_client_to_server:
            sending_bytes += packet_3.packet_length

    # ---------------------------------------------------------
    # TTL values
    # ---------------------------------------------------------
    #
    # Our DNS transaction currently stores answer record types
    # and A-record IPs.
    #
    # The parser also stores TTL inside each DNS answer, but the
    # transaction does not yet preserve those TTL values.
    #
    # Therefore this first validation cannot yet obtain TTLs
    # directly from the transaction.
    #
    # We use an empty list temporarily.
    #
    # IMPORTANT:
    # This will be fixed before XGBoost integration.
    # ---------------------------------------------------------

    ttl_values = []

    # ---------------------------------------------------------
    # Build the 23-feature vector
    # ---------------------------------------------------------

    feature_vector = build_feature_vector(
        domain=transaction.query_name,
        packet_lengths=packet_lengths,
        duration=duration,
        src_port=transaction.client_port,
        sending_bytes=sending_bytes,
        ttl_values=ttl_values,
        answer_record_types=transaction.answer_record_types,
    )

    # ---------------------------------------------------------
    # Display results
    # ---------------------------------------------------------

    print()
    print("========================================")
    print("       DNS FEATURE PIPELINE")
    print("========================================")

    print()
    print("Domain:")
    print(transaction.query_name)

    print()
    print("Packet lengths:")
    print(packet_lengths)

    print()
    print("Duration:")
    print(duration)

    print()
    print("Sending bytes:")
    print(sending_bytes)

    print()
    print("Answer record types:")
    print(transaction.answer_record_types)

    print()
    print("Feature vector:")
    print()

    for name, value in zip(
        FEATURE_ORDER,
        feature_vector,
    ):
        print(
            f"{name:45s} : {value}"
        )

    print()
    print("Feature count:")
    print(len(feature_vector))

    print()
    print("Expected feature count:")
    print(len(FEATURE_ORDER))

    print()
    print("Feature order:")
    print(FEATURE_ORDER)

    print()
    print("========================================")