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

    # ---------------------------------------------------------
    # Base timestamp
    # ---------------------------------------------------------
    #
    # Every packet gets an explicit timestamp.
    #
    # This is important because the DNS feature extractor uses
    # query_timestamp and response_timestamp to calculate:
    #
    #     duration
    #
    # which then affects:
    #
    #     packets_rate
    #     packets_len_rate
    #
    base_time = 1_790_591_945.000000

    packets = []

    # =========================================================
    # DNS
    # =========================================================

    # ---------------------------------------------------------
    # DNS Transaction 1
    # example.com
    # ---------------------------------------------------------

    dns_query_1 = (
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

    dns_response_1 = (
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

    dns_query_1.time = base_time
    dns_response_1.time = base_time + 0.025

    # ---------------------------------------------------------
    # DNS Transaction 2
    # google.com
    # ---------------------------------------------------------

    dns_query_2 = (
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
            sport=53001,
            dport=53
        )
        /
        DNS(
            id=101,
            rd=1,
            qd=DNSQR(
                qname="google.com",
                qtype="A"
            )
        )
    )

    dns_response_2 = (
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
            dport=53001
        )
        /
        DNS(
            id=101,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(
                qname="google.com",
                qtype="A"
            ),
            an=DNSRR(
                rrname="google.com",
                type="A",
                ttl=300,
                rdata="142.250.72.14"
            )
        )
    )

    dns_query_2.time = base_time + 0.050
    dns_response_2.time = base_time + 0.080

    # ---------------------------------------------------------
    # DNS Transaction 3
    # openai.com
    # ---------------------------------------------------------

    dns_query_3 = (
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
            sport=53002,
            dport=53
        )
        /
        DNS(
            id=102,
            rd=1,
            qd=DNSQR(
                qname="openai.com",
                qtype="A"
            )
        )
    )

    dns_response_3 = (
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
            dport=53002
        )
        /
        DNS(
            id=102,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(
                qname="openai.com",
                qtype="A"
            ),
            an=DNSRR(
                rrname="openai.com",
                type="A",
                ttl=300,
                rdata="104.18.33.45"
            )
        )
    )

    dns_query_3.time = base_time + 0.100
    dns_response_3.time = base_time + 0.140

    # ---------------------------------------------------------
    # DNS Transaction 4
    # www.github.com
    # ---------------------------------------------------------

    dns_query_4 = (
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
            sport=53003,
            dport=53
        )
        /
        DNS(
            id=103,
            rd=1,
            qd=DNSQR(
                qname="www.github.com",
                qtype="A"
            )
        )
    )

    dns_response_4 = (
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
            dport=53003
        )
        /
        DNS(
            id=103,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(
                qname="www.github.com",
                qtype="A"
            ),
            an=DNSRR(
                rrname="www.github.com",
                type="A",
                ttl=300,
                rdata="140.82.112.4"
            )
        )
    )

    dns_query_4.time = base_time + 0.160
    dns_response_4.time = base_time + 0.210

    # ---------------------------------------------------------
    # Add all DNS packets
    # ---------------------------------------------------------

    packets.extend(
        [
            dns_query_1,
            dns_response_1,
            dns_query_2,
            dns_response_2,
            dns_query_3,
            dns_response_3,
            dns_query_4,
            dns_response_4,
        ]
    )

    # =========================================================
    # HTTP
    # =========================================================

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

    # Explicit HTTP timestamps.
    http_request.time = base_time + 0.100
    http_response.time = base_time + 0.125

    packets.extend(
        [
            http_request,
            http_response
        ]
    )

    # =========================================================
    # HTTPS / TLS-like traffic
    # =========================================================

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

    # Explicit TLS timestamps.
    tls_request.time = base_time + 0.200
    tls_response.time = base_time + 0.225

    packets.extend(
        [
            tls_request,
            tls_response
        ]
    )

    # =========================================================
    # SSH
    # =========================================================

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

    # Explicit SSH timestamps.
    ssh_request.time = base_time + 0.300
    ssh_response.time = base_time + 0.325

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