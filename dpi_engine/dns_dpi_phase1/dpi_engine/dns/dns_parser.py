import struct


class DNSParser:

    DNS_HEADER_SIZE = 12

    def parse(self, payload):

        if len(payload) < self.DNS_HEADER_SIZE:
            return None

        transaction_id = struct.unpack(
            "!H",
            payload[0:2]
        )[0]

        flags = struct.unpack(
            "!H",
            payload[2:4]
        )[0]

        question_count = struct.unpack(
            "!H",
            payload[4:6]
        )[0]

        answer_count = struct.unpack(
            "!H",
            payload[6:8]
        )[0]

        authority_count = struct.unpack(
            "!H",
            payload[8:10]
        )[0]

        additional_count = struct.unpack(
            "!H",
            payload[10:12]
        )[0]

        is_response = bool(
            flags & 0x8000
        )

        result = {
            "transaction_id": transaction_id,
            "is_response": is_response,
            "question_count": question_count,
            "answer_count": answer_count,
            "authority_count": authority_count,
            "additional_count": additional_count,

            "query_name": None,
            "query_type": None,
            "query_class": None,

            "answers": [],

            # Numeric DNS RR type codes from the answer section.
            #
            # Example:
            #   CNAME = 5
            #   A     = 1
            #
            # Therefore:
            #   [5, 5, 1, 1]
            #
            # This is required by the ALFlowLyzer-compatible
            # distinct_A_records feature.
            "answer_record_types": [],
        }

        offset = self.DNS_HEADER_SIZE

        # -------------------------
        # Question section
        # -------------------------

        if question_count > 0:

            query_name, offset = self._read_name(
                payload,
                offset
            )

            if query_name is None:
                return result

            result["query_name"] = query_name

            if offset + 4 > len(payload):
                return result

            query_type = struct.unpack(
                "!H",
                payload[offset:offset + 2]
            )[0]

            query_class = struct.unpack(
                "!H",
                payload[offset + 2:offset + 4]
            )[0]

            result["query_type"] = (
                self._record_type(query_type)
            )

            result["query_class"] = query_class

            offset += 4

        # -------------------------
        # Answer section
        # -------------------------

        for _ in range(answer_count):

            answer, offset = self._read_answer(
                payload,
                offset
            )

            if answer is None:
                break

            result["answers"].append(
                answer
            )

            # Preserve the numeric RR type code.
            #
            # Example:
            #   A     -> 1
            #   CNAME -> 5
            #
            # This is intentionally separate from
            # answer["type"], which remains the human-readable
            # string used by the existing parser.
            result["answer_record_types"].append(
                answer["type_code"]
            )

        return result

    def _read_answer(self, payload, offset):

        name, offset = self._read_name(
            payload,
            offset
        )

        if name is None:
            return None, offset

        if offset + 10 > len(payload):
            return None, offset

        record_type = struct.unpack(
            "!H",
            payload[offset:offset + 2]
        )[0]

        record_class = struct.unpack(
            "!H",
            payload[offset + 2:offset + 4]
        )[0]

        ttl = struct.unpack(
            "!I",
            payload[offset + 4:offset + 8]
        )[0]

        data_length = struct.unpack(
            "!H",
            payload[offset + 8:offset + 10]
        )[0]

        offset += 10

        if offset + data_length > len(payload):
            return None, offset

        record_data = payload[
            offset:offset + data_length
        ]

        offset += data_length

        record = {
            "name": name,

            # Existing human-readable representation.
            "type": self._record_type(record_type),

            # New numeric representation required by the
            # ALFlowLyzer-compatible feature extractor.
            "type_code": record_type,

            "class": record_class,
            "ttl": ttl,
            "data": None,
        }

        # A record
        if record_type == 1 and data_length == 4:

            record["data"] = ".".join(
                str(byte)
                for byte in record_data
            )

        # AAAA record
        elif record_type == 28 and data_length == 16:

            groups = []

            for i in range(0, 16, 2):

                value = struct.unpack(
                    "!H",
                    record_data[i:i + 2]
                )[0]

                groups.append(
                    f"{value:x}"
                )

            record["data"] = ":".join(
                groups
            )

        # CNAME / NS / PTR
        elif record_type in (2, 5, 12):

            name_data, _ = self._read_name(
                payload,
                offset - data_length
            )

            record["data"] = name_data

        # TXT and other records
        else:

            record["data"] = record_data.hex()

        return record, offset

    def _read_name(self, payload, offset):

        labels = []

        original_offset = offset

        jumped = False

        visited = set()

        while offset < len(payload):

            if offset in visited:
                return None, offset

            visited.add(offset)

            length = payload[offset]

            offset += 1

            # End of DNS name
            if length == 0:
                break

            # DNS compression pointer
            if length & 0xC0 == 0xC0:

                if offset >= len(payload):
                    return None, offset

                pointer = (
                    ((length & 0x3F) << 8)
                    | payload[offset]
                )

                offset += 1

                if not jumped:
                    original_offset = offset

                offset = pointer

                jumped = True

                continue

            if offset + length > len(payload):
                return None, offset

            label = payload[
                offset:offset + length
            ]

            try:

                labels.append(
                    label.decode("ascii")
                )

            except UnicodeDecodeError:

                labels.append(
                    label.decode(
                        "ascii",
                        errors="replace"
                    )
                )

            offset += length

        if jumped:
            return ".".join(labels), original_offset

        return ".".join(labels), offset

    @staticmethod
    def _record_type(record_type):

        types = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            65: "HTTPS",
        }

        return types.get(
            record_type,
            f"TYPE{record_type}"
        )