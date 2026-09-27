class ProtocolDetector:

    TCP_PORTS = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS/TLS",
        465: "SMTPS",
        587: "SMTP",
        993: "IMAPS",
        995: "POP3S",
    }

    UDP_PORTS = {
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        123: "NTP",
        161: "SNMP",
        162: "SNMP",
        443: "QUIC",
    }

    def detect(self, packet):

        if packet.ip_protocol == 6:

            return self.TCP_PORTS.get(
                packet.src_port,
                self.TCP_PORTS.get(
                    packet.dst_port
                )
            )

        if packet.ip_protocol == 17:

            return self.UDP_PORTS.get(
                packet.src_port,
                self.UDP_PORTS.get(
                    packet.dst_port
                )
            )

        if packet.ip_protocol == 1:
            return "ICMP"

        return "UNKNOWN"