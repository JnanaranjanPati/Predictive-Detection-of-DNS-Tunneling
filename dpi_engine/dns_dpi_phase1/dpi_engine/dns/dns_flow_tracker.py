from collections import defaultdict

from .dns_transaction import DNSTransaction
from .dns_parser import DNSParser


class DNSFlowTracker:

    def __init__(self):

        self.dns_parser = DNSParser()

        self.pending_transactions = {}

        self.transactions = []

        self.flow_queries = defaultdict(list)

        self.flow_responses = defaultdict(list)

    def process_packet(self, packet):

        # Only process DNS traffic.
        #
        # DNS normally uses port 53 for both queries and responses.
        if (
            packet.src_port != 53
            and packet.dst_port != 53
        ):
            return None

        parsed_dns = self.dns_parser.parse(
            packet.payload
        )

        if parsed_dns is None:
            return None

        transaction_id = parsed_dns[
            "transaction_id"
        ]

        # =========================================================
        # DNS QUERY
        # =========================================================

        if not parsed_dns["is_response"]:

            # The sender of the DNS query is the client.
            client_ip = packet.src_ip
            client_port = packet.src_port

            # The destination is the DNS server.
            server_ip = packet.dst_ip
            server_port = packet.dst_port

            # -----------------------------------------------------
            # Create DNS transaction
            # -----------------------------------------------------
            transaction = DNSTransaction(
                transaction_id=transaction_id,

                client_ip=client_ip,
                client_port=client_port,

                server_ip=server_ip,
                server_port=server_port,

                query_name=parsed_dns[
                    "query_name"
                ],

                query_type=parsed_dns[
                    "query_type"
                ],

                query_timestamp=packet.timestamp,

                # -------------------------------------------------
                # Packet-level statistics
                # -------------------------------------------------

                # The query packet belongs to this transaction.
                packet_lengths=[
                    packet.original_length
                ],

                # Preserve the IP TTL of the query packet.
                ttl_values=(
                    [packet.ttl]
                    if packet.ttl is not None
                    else []
                ),

                # The query is sent by the DNS client, therefore
                # its bytes contribute to sending_bytes.
                sending_bytes=packet.original_length,
            )

            # Build the key used to match the response
            # with this query.
            key = self._transaction_key(
                transaction_id,
                client_ip,
                client_port,
                server_ip,
                server_port,
            )

            self.pending_transactions[key] = (
                transaction
            )

            # Group transactions by client/server flow.
            flow_key = (
                client_ip,
                server_ip,
            )

            self.flow_queries[
                flow_key
            ].append(transaction)

            return transaction

        # =========================================================
        # DNS RESPONSE
        # =========================================================

        # For a response, the destination is the original
        # DNS client.
        client_ip = packet.dst_ip
        client_port = packet.dst_port

        # The source is the DNS server.
        server_ip = packet.src_ip
        server_port = packet.src_port

        # Construct the same transaction key used for the query.
        key = self._transaction_key(
            transaction_id,
            client_ip,
            client_port,
            server_ip,
            server_port,
        )

        # Find the corresponding pending query.
        transaction = (
            self.pending_transactions.get(key)
        )

        # If there is no matching query, we cannot associate
        # this response with a transaction.
        if transaction is None:
            return None

        # =========================================================
        # Preserve response packet statistics
        # =========================================================

        # The response packet also belongs to this DNS
        # transaction.
        transaction.packet_lengths.append(
            packet.original_length
        )

        # Preserve the response IP TTL.
        if packet.ttl is not None:

            transaction.ttl_values.append(
                packet.ttl
            )

        # IMPORTANT:
        #
        # We DO NOT add the response length to
        # transaction.sending_bytes.
        #
        # sending_bytes represents bytes sent by the DNS client.
        # The response is sent by the DNS server.

        transaction.response_received = True

        # ---------------------------------------------------------
        # Preserve DNS answer RR type codes
        # ---------------------------------------------------------
        #
        # Example:
        #
        #   CNAME
        #   CNAME
        #   A
        #   A
        #
        # becomes:
        #
        #   [5, 5, 1, 1]
        #
        # This is required by the ALFlowLyzer-compatible
        # distinct_A_records feature.
        #
        # IMPORTANT:
        # We preserve ALL answer record types, not only A records.

        for answer in parsed_dns["answers"]:

            transaction.answer_record_types.append(
                answer["type_code"]
            )

            # -----------------------------------------------------
            # Preserve A-record IP addresses separately
            # -----------------------------------------------------
            #
            # response_ips is still useful for other analysis.
            # It is NOT used to calculate distinct_A_records,
            # because ALFlowLyzer counts A RR records rather than
            # unique IP addresses.

            if answer["type"] == "A":

                if (
                    answer["data"]
                    not in transaction.response_ips
                ):

                    transaction.response_ips.append(
                        answer["data"]
                    )

        # Record when the DNS response was received.
        transaction.response_timestamp = (
            packet.timestamp
        )

        # Add the completed transaction to the
        # client/server response flow.
        self.flow_responses[
            (client_ip, server_ip)
        ].append(transaction)

        # Store the completed transaction.
        self.transactions.append(
            transaction
        )

        # Remove it from pending transactions because
        # the query/response pair is now complete.
        del self.pending_transactions[key]

        return transaction

    @staticmethod
    def _transaction_key(
        transaction_id,
        client_ip,
        client_port,
        server_ip,
        server_port,
    ):

        return (
            transaction_id,
            client_ip,
            client_port,
            server_ip,
            server_port,
        )

    def get_transactions(self):

        return self.transactions

    def get_queries(self):

        result = []

        for queries in self.flow_queries.values():
            result.extend(queries)

        return result

    def get_flow_summary(self):

        summary = []

        for flow_key, queries in (
            self.flow_queries.items()
        ):

            client_ip, server_ip = flow_key

            responses = self.flow_responses.get(
                flow_key,
                []
            )

            summary.append(
                {
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "queries": len(queries),
                    "responses": len(responses),
                    "completed_transactions": sum(
                        1
                        for transaction in queries
                        if transaction.response_received
                    ),
                }
            )

        return summary