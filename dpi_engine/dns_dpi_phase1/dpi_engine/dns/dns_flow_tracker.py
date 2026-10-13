
from collections import OrderedDict

from .dns_transaction import DNSTransaction
from .dns_parser import DNSParser


class DNSFlowTracker:

    def __init__(
        self,
        transaction_timeout=30.0,
        max_history=10000,
        max_flow_history=1000,
        max_tracked_flows=1000,
    ):
        if transaction_timeout <= 0:
            raise ValueError(
                "transaction_timeout must be greater than 0"
            )

        for name, value in (
            ("max_history", max_history),
            ("max_flow_history", max_flow_history),
            ("max_tracked_flows", max_tracked_flows),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

        self.dns_parser = DNSParser()
        self.transaction_timeout = float(transaction_timeout)

        self.max_history = max_history
        self.max_flow_history = max_flow_history
        self.max_tracked_flows = max_tracked_flows

        # Pending queries are removed when they expire or complete.
        self.pending_transactions = {}

        # Bounded history of completed transactions.
        self.transactions = []

        # Ordered mappings let us evict the oldest tracked flows.
        self.flow_queries = OrderedDict()
        self.flow_responses = OrderedDict()

        self.expired_transaction_count = 0

        # Lifetime counters are independent of retained history.
        self.total_queries_seen = 0
        self.total_responses_matched = 0
        self.total_transactions_completed = 0

    def expire_pending_transactions(self, current_timestamp):
        """Remove pending transactions that have exceeded the timeout."""

        expired_keys = []

        for key, transaction in self.pending_transactions.items():
            query_timestamp = transaction.query_timestamp

            if query_timestamp is None:
                continue

            elapsed = current_timestamp - query_timestamp

            if elapsed >= self.transaction_timeout:
                expired_keys.append(key)

        for key in expired_keys:
            del self.pending_transactions[key]

        self.expired_transaction_count += len(expired_keys)

        return len(expired_keys)

    def _append_flow_history(self, history, flow_key, transaction):
        """Append a record while bounding both flow count and history size."""

        if flow_key not in history:
            history[flow_key] = []

        # Recently active flows move to the end.
        history.move_to_end(flow_key)

        records = history[flow_key]
        records.append(transaction)

        # Keep only the most recent records for this flow.
        if len(records) > self.max_flow_history:
            del records[:-self.max_flow_history]

        # Evict the least recently used flow key.
        while len(history) > self.max_tracked_flows:
            history.popitem(last=False)

    def process_packet(self, packet):
        self.expire_pending_transactions(packet.timestamp)

        # Only process DNS traffic.
        if packet.src_port != 53 and packet.dst_port != 53:
            return None

        parsed_dns = self.dns_parser.parse(packet.payload)

        if parsed_dns is None:
            return None

        transaction_id = parsed_dns["transaction_id"]

        # ---------------------------------------------------------
        # DNS QUERY
        # ---------------------------------------------------------
        if not parsed_dns["is_response"]:
            client_ip = packet.src_ip
            client_port = packet.src_port
            server_ip = packet.dst_ip
            server_port = packet.dst_port

            key = self._transaction_key(
                transaction_id,
                client_ip,
                client_port,
                server_ip,
                server_port,
            )

            # Avoid overwriting a pending query with the same key.
            if key in self.pending_transactions:
                return self.pending_transactions[key]

            transaction = DNSTransaction(
                transaction_id=transaction_id,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                query_name=parsed_dns["query_name"],
                query_type=parsed_dns["query_type"],
                query_timestamp=packet.timestamp,
                packet_lengths=[packet.original_length],
                ttl_values=(
                    [packet.ttl] if packet.ttl is not None else []
                ),
                sending_bytes=packet.original_length,
            )

            self.pending_transactions[key] = transaction
            self.total_queries_seen += 1

            flow_key = (client_ip, server_ip)
            self._append_flow_history(
                self.flow_queries,
                flow_key,
                transaction,
            )

            return transaction

        # ---------------------------------------------------------
        # DNS RESPONSE
        # ---------------------------------------------------------
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

        transaction = self.pending_transactions.get(key)

        # Ignore responses without a matching pending query.
        if transaction is None:
            return None

        transaction.packet_lengths.append(packet.original_length)

        if packet.ttl is not None:
            transaction.ttl_values.append(packet.ttl)

        transaction.response_received = True

        for answer in parsed_dns["answers"]:
            transaction.answer_record_types.append(
                answer["type_code"]
            )

            if answer["type"] == "A":
                if answer["data"] not in transaction.response_ips:
                    transaction.response_ips.append(answer["data"])

        transaction.response_timestamp = packet.timestamp

        flow_key = (client_ip, server_ip)

        self._append_flow_history(
            self.flow_responses,
            flow_key,
            transaction,
        )

        self.transactions.append(transaction)

        # Retain only the most recent completed transactions.
        if len(self.transactions) > self.max_history:
            del self.transactions[:-self.max_history]

        self.total_responses_matched += 1
        self.total_transactions_completed += 1

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
        """Return the retained completed-transaction history."""
        return self.transactions

    def get_queries(self):
        """Return queries still present in the bounded flow history."""
        result = []

        for queries in self.flow_queries.values():
            result.extend(queries)

        return result

    def get_flow_summary(self):
        """Summarize the currently retained per-flow history."""
        summary = []

        flow_keys = list(
            dict.fromkeys(
                list(self.flow_queries.keys())
                + list(self.flow_responses.keys())
            )
        )

        for flow_key in flow_keys:
            client_ip, server_ip = flow_key

            queries = self.flow_queries.get(flow_key, [])
            responses = self.flow_responses.get(flow_key, [])

            summary.append({
                "client_ip": client_ip,
                "server_ip": server_ip,
                "queries": len(queries),
                "responses": len(responses),
                "completed_transactions": sum(
                    1
                    for transaction in queries
                    if transaction.response_received
                ),
            })

        return summary
