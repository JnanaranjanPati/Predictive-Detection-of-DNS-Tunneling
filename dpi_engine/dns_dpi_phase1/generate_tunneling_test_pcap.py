from pathlib import Path

from scapy.all import (
    Ether,
    IP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    wrpcap,
)


OUTPUT = Path(
    "pcaps/tunneling_test.pcap"
)


def build_packets():

    client_mac = "00:11:22:33:44:55"
    server_mac = "66:77:88:99:aa:bb"

    client_ip = "192.168.1.10"
    dns_server_ip = "8.8.8.8"

    base_time = 1_790_592_945.000000

    packets = []

    # =========================================================
    # DNS Transaction 1
    # Long alphanumeric subdomain
    # =========================================================

    domain_1 = (
        "a7f3k9m2x8q4p6v1"
        ".example.com"
    )

    query_1 = (
        Ether(
            src=client_mac,
            dst=server_mac
        )
        /
        IP(
            src=client_ip,
            dst=dns_server_ip,
            ttl=64
        )
        /
        UDP(
            sport=54000,
            dport=53
        )
        /
        DNS(
            id=200,
            rd=1,
            qd=DNSQR(
                qname=domain_1,
                qtype="A"
            )
        )
    )

    response_1 = (
        Ether(
            src=server_mac,
            dst=client_mac
        )
        /
        IP(
            src=dns_server_ip,
            dst=client_ip,
            ttl=117
        )
        /
        UDP(
            sport=53,
            dport=54000
        )
        /
        DNS(
            id=200,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(
                qname=domain_1,
                qtype="A"
            ),
            an=DNSRR(
                rrname=domain_1,
                type="A",
                ttl=300,
                rdata="10.10.10.10"
            )
        )
    )

    query_1.time = base_time
    response_1.time = base_time + 0.030

    packets.extend(
        [
            query_1,
            response_1
        ]
    )

    # =========================================================
    # DNS Transaction 2
    # High-entropy hexadecimal-looking subdomain
    # =========================================================

    domain_2 = (
        "9f3a7c1e5b8d2f6a4c0e9b7d3a1f8c6"
        ".example.com"
    )

    query_2 = (
        Ether(
            src=client_mac,
            dst=server_mac
        )
        /
        IP(
            src=client_ip,
            dst=dns_server_ip,
            ttl=64
        )
        /
        UDP(
            sport=54001,
            dport=53
        )
        /
        DNS(
            id=201,
            rd=1,
            qd=DNSQR(
                qname=domain_2,
                qtype="A"
            )
        )
    )

    response_2 = (
        Ether(
            src=server_mac,
            dst=client_mac
        )
        /
        IP(
            src=dns_server_ip,
            dst=client_ip,
            ttl=117
        )
        /
        UDP(
            sport=53,
            dport=54001
        )
        /
        DNS(
            id=201,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(
                qname=domain_2,
                qtype="A"
            ),
            an=DNSRR(
                rrname=domain_2,
                type="A",
                ttl=300,
                rdata="10.10.10.11"
            )
        )
    )

    query_2.time = base_time + 0.100
    response_2.time = base_time + 0.135

    packets.extend(
        [
            query_2,
            response_2
        ]
    )

    # =========================================================
    # DNS Transaction 3
    # Long mixed alphanumeric subdomain
    # =========================================================

    domain_3 = (
        "x7k2m9p4q8z1"
        "a6c3v8n5b2d9"
        "f4g7h1j6k3l8"
        ".tunnel-test.com"
    )

    query_3 = (
        Ether(
            src=client_mac,
            dst=server_mac
        )
        /
        IP(
            src=client_ip,
            dst=dns_server_ip,
            ttl=64
        )
        /
        UDP(
            sport=54002,
            dport=53
        )
        /
        DNS(
            id=202,
            rd=1,
            qd=DNSQR(
                qname=domain_3,
                qtype="A"
            )
        )
    )

    response_3 = (
        Ether(
            src=server_mac,
            dst=client_mac
        )
        /
        IP(
            src=dns_server_ip,
            dst=client_ip,
            ttl=117
        )
        /
        UDP(
            sport=53,
            dport=54002
        )
        /
        DNS(
            id=202,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(
                qname=domain_3,
                qtype="A"
            ),
            an=DNSRR(
                rrname=domain_3,
                type="A",
                ttl=300,
                rdata="10.10.10.12"
            )
        )
    )

    query_3.time = base_time + 0.200
    response_3.time = base_time + 0.245

    packets.extend(
        [
            query_3,
            response_3
        ]
    )

    # =========================================================
    # DNS Transaction 4
    # Long high-entropy encoded-looking subdomain
    # =========================================================

    domain_4 = (
        "k9x7m2p4q8v1"
        "z6c3n5b8d2f7"
        "g4h9j1l6s3w8"
        "r5t2y7u4i9o1"
        ".tunnel-test.com"
    )

    query_4 = (
        Ether(
            src=client_mac,
            dst=server_mac
        )
        /
        IP(
            src=client_ip,
            dst=dns_server_ip,
            ttl=64
        )
        /
        UDP(
            sport=54003,
            dport=53
        )
        /
        DNS(
            id=203,
            rd=1,
            qd=DNSQR(
                qname=domain_4,
                qtype="A"
            )
        )
    )

    response_4 = (
        Ether(
            src=server_mac,
            dst=client_mac
        )
        /
        IP(
            src=dns_server_ip,
            dst=client_ip,
            ttl=117
        )
        /
        UDP(
            sport=53,
            dport=54003
        )
        /
        DNS(
            id=203,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(
                qname=domain_4,
                qtype="A"
            ),
            an=DNSRR(
                rrname=domain_4,
                type="A",
                ttl=300,
                rdata="10.10.10.13"
            )
        )
    )

    query_4.time = base_time + 0.300
    response_4.time = base_time + 0.355

    packets.extend(
        [
            query_4,
            response_4
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