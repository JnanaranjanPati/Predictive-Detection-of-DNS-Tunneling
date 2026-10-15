
from pathlib import Path
from collections import Counter

from scapy.all import PcapReader, DNS, DNSQR, DNSRR

PCAP_FILES = [
    Path("pcaps/test_traffic.pcap"),
    Path("pcaps/tunneling_test.pcap"),
]


def inspect_pcap(path):
    print("\n" + "=" * 60)
    print(f"PCAP: {path}")
    print("=" * 60)

    if not path.exists():
        print("File not found.")
        return

    packet_count = 0
    dns_packets = 0
    dns_queries = 0
    dns_responses = 0
    query_names = set()
    protocols = Counter()

    with PcapReader(str(path)) as reader:
        for packet in reader:
            packet_count += 1

            if packet.haslayer("IP"):
                if packet.haslayer("UDP"):
                    protocols["UDP"] += 1
                elif packet.haslayer("TCP"):
                    protocols["TCP"] += 1
                else:
                    protocols["Other IP"] += 1
            else:
                protocols["Non-IPv4"] += 1

            if packet.haslayer(DNS):
                dns_packets += 1
                dns = packet[DNS]

                if dns.qr == 0:
                    dns_queries += 1
                    if dns.qd is not None and packet.haslayer(DNSQR):
                        name = dns.qd.qname
                        if isinstance(name, bytes):
                            name = name.decode("utf-8", errors="replace")
                        query_names.add(str(name))
                else:
                    dns_responses += 1

    print(f"Total packets: {packet_count}")
    print(f"DNS packets: {dns_packets}")
    print(f"DNS queries: {dns_queries}")
    print(f"DNS responses: {dns_responses}")
    print(f"Unique queried domains: {len(query_names)}")
    print(f"Protocol counts: {dict(protocols)}")

    if query_names:
        print("Sample queried domains:")
        for name in sorted(query_names)[:10]:
            print(f"  {name}")


if __name__ == "__main__":
    for pcap_file in PCAP_FILES:
        inspect_pcap(pcap_file)
