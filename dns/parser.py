import struct
from dns.protocol import DNSQuestion, DNSRecord, DNSMessage


class DNSParser:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    @classmethod
    def parse(cls, data: bytes) -> DNSMessage:
        parser = cls(data)
        return parser._parse_message()

    def _parse_message(self) -> DNSMessage:
        """Разбирает пакет по секциям"""

        header = struct.unpack('!HHHHHH', self.data[:12])
        self.offset = 12

        transaction_id = header[0]
        flags = header[1]
        qdcount = header[2]
        ancount = header[3]
        nscount = header[4]
        arcount = header[5]

        questions = []
        for _ in range(qdcount):
            questions.append(self._parse_question())

        # Читаем секцию ответов (AN), пойдет в кеш
        answers = []
        for _ in range(ancount):
            answers.append(self._parse_record())

        # Читаем секцию авторитетных серверов (NS)
        authority = []
        for _ in range(nscount):
            authority.append(self._parse_record())

        # Читаем секцию дополнительных записей (AR)
        additional = []
        for _ in range(arcount):
            additional.append(self._parse_record())

        # Возвращаем полностью собранный объект
        return DNSMessage(
            transaction_id=transaction_id,
            flags=flags,
            questions=questions,
            answers=answers,
            authority=authority,
            additional=additional
        )

    def _parse_question(self) -> DNSQuestion:
        # Сначала читаем имя домена (оно может быть любой длины)
        name = self._parse_name()

        # Затем читаем тип и класс (по 2 байта каждый)
        qtype, qclass = struct.unpack('!HH', self.data[self.offset:self.offset + 4])
        self.offset += 4

        return DNSQuestion(name, qtype, qclass)

    def _parse_record(self) -> DNSRecord:
        name = self._parse_name()

        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', self.data[self.offset:self.offset + 10])
        self.offset += 10

        rdata = self.data[self.offset:self.offset + rdlength]
        self.offset += rdlength

        return DNSRecord(name, rtype, rclass, ttl, rdlength, rdata)

    def _parse_name(self) -> str:
        labels = []
        jumped = False
        curr = self.offset

        while True:
            # Читаем один байт (длину следующего куска текста или маркер указателя)
            length = self.data[curr]

            # Если 0 - это конец имени
            if length == 0:
                curr += 1
                if not jumped:
                    # Если мы не прыгали по указателям, основной курсор сдвигается сюда
                    self.offset = curr
                break

            # Проверяем, является ли байт указателем (маска 11000000 в бинарном = 0xC0)
            if (length & 0xC0) == 0xC0:
                # Указатель занимает 2 байта. Читаем их.
                pointer = struct.unpack('!H', self.data[curr:curr + 2])[0]
                # Убираем первые 2 бита (маска 0x3FFF), чтобы получить чистое смещение от начала пакета
                target_offset = pointer & 0x3FFF

                if not jumped:
                    # Основной курсор сдвигается ровно на 2 байта (размер указателя)
                    self.offset = curr + 2
                    jumped = True  # Дальше основной курсор не двигаем!

                # Перемещаем временный курсор по указателю и продолжаем читать оттуда
                curr = target_offset
            else:
                # Это обычный кусок текста (label)
                curr += 1
                label = self.data[curr:curr + length].decode('utf-8', errors='ignore')
                labels.append(label)
                curr += length

                if not jumped:
                    self.offset = curr

        return ".".join(labels)
