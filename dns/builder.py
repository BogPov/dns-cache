import struct
from typing import List

from .protocol import DNSQuestion, DNSMessage, DNSRecord


class DNSBuilder:
    @classmethod
    def build_response(cls, request: DNSMessage, answers: List[DNSRecord]) -> bytes:
        builder = cls()
        return builder._build(request, answers)

    def _build(self, request: DNSMessage, answers: List[DNSRecord]) -> bytes:
        response_flags = request.flags | 0x8000

        header = self._build_header(
            request.transaction_id,
            response_flags,
            len(request.questions),
            len(answers),
            0,
            0
        )

        questions_bytes = b''.join(self._build_question(q) for q in request.questions)
        answers_bytes = b''.join(self._build_record(a) for a in answers)

        return header + questions_bytes + answers_bytes

    def _build_header(self, tx_id: int, flags: int, qdcount: int, ancount: int, nscount: int, arcount: int) -> bytes:
        return struct.pack('!HHHHHH', tx_id, flags, qdcount, ancount, nscount, arcount)

    def _build_question(self, q: DNSQuestion) -> bytes:
        name_bytes = self._build_name(q.name)
        type_class_bytes = struct.pack('!HH', q.qtype, q.qclass)
        return name_bytes + type_class_bytes

    def _build_record(self, r: DNSRecord) -> bytes:
        name_bytes = self._build_name(r.name)
        meta_bytes = struct.pack('!HHIH', r.rtype, r.rclass, int(r.ttl), len(r.data))
        return name_bytes + meta_bytes + r.data

    def _build_name(self, name: str) -> bytes:
        if not name or name == '.':
            return b'\x00'

        result = b''
        for label in name.split('.'):
            label_bytes = label.encode('utf-8')
            result += struct.pack('B', len(label_bytes)) + label_bytes

        result += b'\x00'
        return result

    @staticmethod
    def build_error_response(request_msg, rcode: int = 2) -> bytes:
        builder = DNSBuilder()

        transaction_id = request_msg.transaction_id

        flags = 0x8000
        flags |= 0x0080
        flags |= rcode

        header = struct.pack(
            '!HHHHHH',
            transaction_id,
            flags,
            len(request_msg.questions),
            0,
            0,
            0
        )

        questions = b''.join(
            builder._build_question(q)
            for q in request_msg.questions
        )

        return header + questions
