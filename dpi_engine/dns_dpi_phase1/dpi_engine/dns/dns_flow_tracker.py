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

        if not parsed_dns["is_response"]:

            client_ip = packet.src_ip
            client_port = packet.src_port

            server_ip = packet.dst_ip
            server_port = packet.dst_port

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
            )

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

            flow_key = (
                client_ip,
                server_ip
            )

            self.flow_queries[
                flow_key
            ].append(transaction)

            return transaction

        # DNS response

        client_ip = packet.dst_ip
        client_port = packet.dst_port

        server_ip = packet.src_ip
        server_port = packet.src_port

        key = self._transaction_key(
            transaction_id,
            client_ip,
            client_port,
            server_ip,
            server_port,
        )

        transaction = (
            self.pending_transactions.get(key)
        )

        if transaction is None:
            return None

        transaction.response_received = True

        for answer in parsed_dns["answers"]:

            if answer["type"] == "A":

                if answer["data"] not in transaction.response_ips:

                    transaction.response_ips.append(
                        answer["data"]
                    )


        transaction.response_timestamp = (
            packet.timestamp
        )

        self.flow_responses[
            (client_ip, server_ip)
        ].append(transaction)

        self.transactions.append(
            transaction
        )

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