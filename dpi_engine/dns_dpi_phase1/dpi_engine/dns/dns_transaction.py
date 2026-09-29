from dataclasses import dataclass
from typing import Optional


@dataclass
class DNSTransaction:

    transaction_id: int

    client_ip: str
    client_port: int

    server_ip: str
    server_port: int

    query_name: Optional[str] = None
    query_type: Optional[str] = None

    query_timestamp: Optional[float] = None
    response_timestamp: Optional[float] = None

    response_received: bool = False

    # A-record IP addresses returned by the DNS response.
    response_ips: list[str] = None

    # Numeric DNS answer RR type codes.
    #
    # Examples:
    #   1  = A
    #   5  = CNAME
    #   28 = AAAA
    #
    # Example:
    #   CNAME, CNAME, A, A
    #
    # becomes:
    #   [5, 5, 1, 1]
    answer_record_types: list[int] = None

    # ---------------------------------------------------------
    # Packet-level statistics required by the existing
    # DNS feature extractor.
    # ---------------------------------------------------------

    # Length of every DNS packet belonging to this transaction.
    packet_lengths: list[int] = None

    # IP TTL values observed in the DNS packets.
    ttl_values: list[int] = None

    # Total bytes sent by the DNS client.
    sending_bytes: int = 0

    def __post_init__(self):

        if self.response_ips is None:
            self.response_ips = []

        if self.answer_record_types is None:
            self.answer_record_types = []

        if self.packet_lengths is None:
            self.packet_lengths = []

        if self.ttl_values is None:
            self.ttl_values = []

    @property
    def response_time(self):

        if (
            self.query_timestamp is None
            or self.response_timestamp is None
        ):
            return None

        return (
            self.response_timestamp
            - self.query_timestamp
        )