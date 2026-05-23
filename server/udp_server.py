import socket
from typing import Tuple
import random
import struct
import time

from utils.logger import get_logger
from dns.parser import DNSParser
from dns.protocol import QTYPES, DNSMessage
from dns.builder import DNSBuilder
from cache.dns_cache import DNSCache

log = get_logger()


class DNSServer:
    HOST = 'localhost'
    RECEIVE_BUFFER_SIZE = 1024

    def __init__(self, port: int, forwarder_host: str, forwarder_port: int):
        self.port = port
        self.forwarder_host = forwarder_host
        self.forwarder_port = forwarder_port

        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__sock.bind((self.HOST, self.port))

        self.__cache = DNSCache()
        self.__only_cache = False

        self.__active_queries = {}

        if self.__is_loop():
            log.warning("Сервер спрашивает сам у себя! Ответы только из кэша!")
            self.__only_cache = True
        elif not self.__confirm_forwarder():
            raise ConnectionError("Forwarder не отвечает")

        log.info(f"Сервер начал работу на порту {self.port}")

    def serve(self):
        while True:
            try:
                data, addr = self.__sock.recvfrom(4096)
                request_msg = DNSParser.parse(data)

                if not request_msg.questions:
                    continue

                question = request_msg.questions[0]
                qtype_str = QTYPES.get(question.qtype, str(question.qtype))

                cached_answers = self.__cache.get(question)

                if cached_answers:
                    log.info(f"{addr[0]}, {qtype_str}, {question.name}, cache")
                    response = DNSBuilder.build_response(request_msg, cached_answers)
                    self.__sock.sendto(response, addr)
                    continue
                elif self.__only_cache:
                    log.error(f'на {addr[0]} был послан error, тк {question.name} не кэширован')
                    error_response = DNSBuilder.build_error_response(request_msg)
                    self.__sock.sendto(error_response, addr)
                    continue

                # защита от зацикливания
                current_time = time.time()
                query_key = (question.name, question.qtype)

                # очищаем старые записи, чтобы не было утечки памяти
                self.__active_queries = {k: t for k, t in self.__active_queries.items() if current_time - t < 5.0}

                if query_key in self.__active_queries:
                    log.warning(f"Петля! Запрос {question.name} от {addr[0]} уже в обработке.)")
                    error_response = DNSBuilder.build_error_response(request_msg)
                    self.__sock.sendto(error_response, addr)
                    continue

                # запоминаем, что мы начали искать этот домен
                self.__active_queries[query_key] = current_time

                # идем к форвардеру
                log.info(f"{addr[0]}, {qtype_str}, {question.name}, forwarder")
                self.__forward_and_cache(data, request_msg, addr)

                self.__cache.save_to_mem()

            except Exception:
                pass

    def __forward_and_cache(self, raw_data: bytes, request_msg: DNSMessage, client_addr: Tuple[str, int]):
        fwd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fwd_sock.settimeout(2.0)

        new_id = random.randint(0, 65535)
        fwd_req = struct.pack('!H', new_id) + raw_data[2:]

        try:
            fwd_sock.sendto(fwd_req, (self.forwarder_host, self.forwarder_port))
            fwd_resp, _ = fwd_sock.recvfrom(4096)

            parsed_resp = DNSParser.parse(fwd_resp)
            self.__cache.put(parsed_resp.answers + parsed_resp.authority + parsed_resp.additional)

            final_resp = struct.pack('!H', request_msg.transaction_id) + fwd_resp[2:]
            self.__sock.sendto(final_resp, client_addr)

        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            fwd_sock.close()

    def __is_loop(self) -> bool:
        return self.port == self.forwarder_port and self.forwarder_host in ('127.0.0.1', 'localhost', '0.0.0.0')

    def __confirm_forwarder(self) -> bool:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.settimeout(2)
        try:
            test_sock.sendto(b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01',
                             (self.forwarder_host, self.forwarder_port))
            test_sock.recv(1024)
            return True
        except socket.timeout:
            return False

        except Exception:
            return False
        finally:
            test_sock.close()
