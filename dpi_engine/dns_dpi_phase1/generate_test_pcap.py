from pathlib import Path

from scapy.all import (
    Ether,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    wrpcap,
)


OUTPUT = Path(
    "pcaps/test_traffic.pcap"
)


def build_packets():

    client = "00:11:22:33:44:55"
    server = "66:77:88:99:aa:bb"

    packets = []

    # DNS query
    dns_query = (
        Ether(
            src=client,
            dst=server
        )
        /
        IP(
            src="192.168.1.10",
            dst="8.8.8.8",
            ttl=64
        )
        /
        UDP(
            sport=53000,
            dport=53
        )
        /
        DNS(
            id=100,
            rd=1,
            qd=DNSQR(
                qname="example.com",
                qtype="A"
            )
        )
    )

    # DNS response
    dns_response = (
        Ether(
            src=server,
            dst=client
        )
        /
        IP(
            src="8.8.8.8",
            dst="192.168.1.10",
            ttl=117
        )
        /
        UDP(
            sport=53,
            dport=53000
        )
        /
        DNS(
            id=100,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(
                qname="example.com",
                qtype="A"
            ),
            an=DNSRR(
                rrname="example.com",
                type="A",
                ttl=300,
                rdata="93.184.216.34"
            )
        )
    )

    packets.extend(
        [
            dns_query,
            dns_response
        ]
    )

    # HTTP
    http_request = (
        Ether(
            src=client,
            dst=server
        )
        /
        IP(
            src="192.168.1.10",
            dst="93.184.216.34",
            ttl=64
        )
        /
        TCP(
            sport=52000,
            dport=80,
            flags="PA",
            seq=1,
            ack=1
        )
        /
        b"GET / HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"\r\n"
    )

    http_response = (
        Ether(
            src=server,
            dst=client
        )
        /
        IP(
            src="93.184.216.34",
            dst="192.168.1.10",
            ttl=52
        )
        /
        TCP(
            sport=80,
            dport=52000,
            flags="PA",
            seq=1,
            ack=1
        )
        /
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 5\r\n"
        b"\r\n"
        b"Hello"
    )

    packets.extend(
        [
            http_request,
            http_response
        ]
    )

    # HTTPS/TLS-like traffic
    tls_request = (
        Ether(
            src=client,
            dst=server
        )
        /
        IP(
            src="192.168.1.10",
            dst="142.250.72.14",
            ttl=64
        )
        /
        TCP(
            sport=52001,
            dport=443,
            flags="PA",
            seq=1,
            ack=1
        )
        /
        b"placeholder TLS payload"
    )

    tls_response = (
        Ether(
            src=server,
            dst=client
        )
        /
        IP(
            src="142.250.72.14",
            dst="192.168.1.10",
            ttl=52
        )
        /
        TCP(
            sport=443,
            dport=52001,
            flags="PA",
            seq=1,
            ack=1
        )
        /
        b"placeholder TLS response"
    )

    packets.extend(
        [
            tls_request,
            tls_response
        ]
    )

    # SSH
    ssh_request = (
        Ether(
            src=client,
            dst=server
        )
        /
        IP(
            src="192.168.1.10",
            dst="192.168.1.20",
            ttl=64
        )
        /
        TCP(
            sport=52002,
            dport=22,
            flags="S",
            seq=100
        )
    )

    ssh_response = (
        Ether(
            src=server,
            dst=client
        )
        /
        IP(
            src="192.168.1.20",
            dst="192.168.1.10",
            ttl=64
        )
        /
        TCP(
            sport=22,
            dport=52002,
            flags="SA",
            seq=200,
            ack=101
        )
    )

    packets.extend(
        [
            ssh_request,
            ssh_response
        ]
    )

    return packets


def main():

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    packets = build_packets()

    wrpcap(
        str(OUTPUT),
        packets
    )

    print(
        f"Created {len(packets)} packets"
    )

    print(
        f"PCAP: {OUTPUT}"
    )


if __name__ == "__main__":
    main()