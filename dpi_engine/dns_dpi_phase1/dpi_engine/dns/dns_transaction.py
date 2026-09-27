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

    response_ips: list[str] = None

    def __post_init__(self):

        if self.response_ips is None:
            self.response_ips = []

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