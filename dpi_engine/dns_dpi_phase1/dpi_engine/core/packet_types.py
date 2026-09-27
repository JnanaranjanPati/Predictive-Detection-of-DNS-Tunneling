from dataclasses import dataclass
from typing import Optional


@dataclass
class RawPacket:
    timestamp: float
    captured_length: int
    original_length: int
    data: bytes


@dataclass
class ParsedPacket:
    timestamp: float

    captured_length: int
    original_length: int

    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ether_type: Optional[int] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    ip_protocol: Optional[int] = None
    ttl: Optional[int] = None

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    tcp_flags: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None

    payload: bytes = b""

    application_protocol: Optional[str] = None

    fragmented: bool = False