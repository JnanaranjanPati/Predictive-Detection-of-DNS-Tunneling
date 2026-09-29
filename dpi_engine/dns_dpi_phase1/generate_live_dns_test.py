from scapy.all import IP, UDP, DNS, DNSQR, send


TARGET_DNS = "10.243.171.123"

TEST_DOMAINS = [
    "a7f3k9m2x8q4p6v1.example.com",
    "9f3a7c1e5b8d2f6a4c0e9b7d3a1f8c6.example.com",
    "x7k2m9p4q8z1a6c3v8n5b2d9f4g7h1j6k3l8.tunnel-test.com",
    "k9x7m2p4q8v1z6c3n5b8d2f7g4h9j1l6s3w8r5t2y7u4i9o1.tunnel-test.com",
]


def main():

    print("Sending live DNS tunneling-like test traffic...")
    print(f"DNS server: {TARGET_DNS}")
    print()

    for index, domain in enumerate(TEST_DOMAINS, start=1):

        print(f"[{index}] Sending query: {domain}")

        packet = (
            IP(dst=TARGET_DNS)
            / UDP(sport=40000 + index, dport=53)
            / DNS(
                id=200 + index,
                rd=1,
                qd=DNSQR(
                    qname=domain,
                    qtype="A"
                )
            )
        )

        send(
            packet,
            verbose=False
        )

    print()
    print("Finished sending test DNS traffic.")


if __name__ == "__main__":
    main()