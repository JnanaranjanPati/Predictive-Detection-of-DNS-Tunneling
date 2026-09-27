import struct
from pathlib import Path

from .packet_types import RawPacket


class PcapReader:
    """
    Reader for classic PCAP files.

    This intentionally supports .pcap rather than PCAPNG.
    """

    MAGIC_NUMBERS = {
        b"\xd4\xc3\xb2\xa1": ("<", "micro"),
        b"\xa1\xb2\xc3\xd4": (">", "micro"),
        b"\x4d\x3c\xb2\xa1": ("<", "nano"),
        b"\xa1\xb2\x3c\x4d": (">", "nano"),
    }

    def __init__(self, filename):
        self.filename = Path(filename)

    def packets(self):
        with self.filename.open("rb") as f:

            global_header = f.read(24)

            if len(global_header) != 24:
                raise ValueError("Invalid PCAP file: incomplete global header")

            magic = global_header[:4]

            if magic not in self.MAGIC_NUMBERS:
                raise ValueError(
                    "Unsupported PCAP format or PCAPNG file detected"
                )

            endian, timestamp_precision = self.MAGIC_NUMBERS[magic]

            packet_header_format = endian + "IIII"

            packet_header_size = struct.calcsize(packet_header_format)

            packet_number = 0

            while True:

                header = f.read(packet_header_size)

                if not header:
                    break

                if len(header) != packet_header_size:
                    raise ValueError(
                        "Incomplete packet header"
                    )

                ts_sec, ts_fraction, captured_length, original_length = (
                    struct.unpack(packet_header_format, header)
                )

                if timestamp_precision == "micro":
                    timestamp = ts_sec + ts_fraction / 1_000_000
                else:
                    timestamp = ts_sec + ts_fraction / 1_000_000_000

                data = f.read(captured_length)

                if len(data) != captured_length:
                    raise ValueError(
                        f"Incomplete packet data at packet {packet_number}"
                    )

                yield RawPacket(
                    timestamp=timestamp,
                    captured_length=captured_length,
                    original_length=original_length,
                    data=data,
                )

                packet_number += 1