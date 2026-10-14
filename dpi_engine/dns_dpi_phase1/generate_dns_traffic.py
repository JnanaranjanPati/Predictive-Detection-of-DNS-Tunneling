
import time
import random

from scapy.all import IP, UDP, DNS, DNSQR, send


DNS_SERVER = "8.8.8.8"

DOMAINS = [
    "google.com",
    "example.com",
    "microsoft.com",
    "github.com",
    "openai.com",
    "wikipedia.org",
    "cloudflare.com",
    "python.org",
    "stackoverflow.com",
    "amazon.com",
    "pypi.org",
    "npmjs.com",
    "apple.com",
    "linkedin.com",
    "discord.com",
]

TOTAL_QUERIES = 100
DELAY_SECONDS = 0.2


def main():

    print("DNS traffic generator started")
    print(f"Destination DNS server: {DNS_SERVER}")
    print(f"Total queries: {TOTAL_QUERIES}")
    print(f"Delay between queries: {DELAY_SECONDS} seconds")
    print("Use only on a network you are authorized to test.")
    print()

    for index in range(TOTAL_QUERIES):

        domain = random.choice(DOMAINS)

        packet = (
            IP(dst=DNS_SERVER)
            / UDP(sport=random.randint(20000, 60000), dport=53)
            / DNS(
                id=random.randint(0, 65535),
                rd=1,
                qd=DNSQR(qname=domain, qtype="A"),
            )
        )

        send(packet, verbose=False)

        print(
            f"[{index + 1}/{TOTAL_QUERIES}] "
            f"Sent DNS query for {domain}"
        )

        time.sleep(DELAY_SECONDS)

    print("\nTraffic generation completed.")


if __name__ == "__main__":
    main()
