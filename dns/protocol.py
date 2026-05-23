from dataclasses import dataclass
from typing import List


QTYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 16: 'TXT', 28: 'AAAA'}


@dataclass
class DNSQuestion:
    """Класс для хранения секции вопроса (Question)"""
    name: str
    qtype: int
    qclass: int


@dataclass
class DNSRecord:
    """Класс для хранения ресурсной записи (Answers, Authority, Additional)"""
    name: str       # имя домена, к которому относится запись
    rtype: int      # тип записи (A, MX, CNAME и т.д.)
    rclass: int     # класс (IN)
    ttl: int        # TTL
    rdlength: int   # длина поля данных
    data: bytes     # сами данные в сыром виде


@dataclass
class DNSMessage:
    """Класс, описывающий весь DNS-пакет целиком"""
    transaction_id: int
    flags: int
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authority: List[DNSRecord]
    additional: List[DNSRecord]
