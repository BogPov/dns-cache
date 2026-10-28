import argparse
import ipaddress
import socket


DEFAULT_PORT = 53
DEFAULT_FORWARDER_HOST = "8.8.8.8"
DEFAULT_FORWARDER_IP = 53


class CLIArgsParser:

    LISTEN_PORT_KEY = "listen_port"
    FORWARD_HOST_KEY = "forward_host"
    FORWARD_PORT_KEY = "forward_port"

    def __init__(self):
        self.parser = self._build_parser()

    def _validate_port(self, value: str) -> int:
        try:
            port = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Порт должен быть числом: '{value}'")

        if not (1 <= port <= 65535):
            raise argparse.ArgumentTypeError(
                f"Порт вне допустимого диапазона (1-65535): {port}"
            )

        return port

    def _validate_host(self, host: str) -> str:
        # Проверка IP
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass

        # Проверка hostname через DNS
        try:
            socket.getaddrinfo(host, None)
            return host
        except socket.gaierror:
            raise argparse.ArgumentTypeError(
                f"Некорректный IP или hostname: '{host}'"
            )

    def _parse_forwarder(self, value: str) -> tuple[str, int]:
        if not value:
            raise argparse.ArgumentTypeError("Форвардер не может быть пустым")

        if ":" in value:
            host_part, port_part = value.rsplit(":", 1)

            if not host_part:
                raise argparse.ArgumentTypeError("Отсутствует хост в форвардере")

            host = self._validate_host(host_part)
            port = self._validate_port(port_part)
        else:
            host = self._validate_host(value)
            port = DEFAULT_PORT

        return host, port

    def _build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="Кэширующий DNS сервер",
            add_help=False
        )

        parser.add_argument(
            "-p", "--port",
            type=self._validate_port,
            default=DEFAULT_PORT,
            required=False,
            help=f"Слушаемый UDP порт (по умолчанию {DEFAULT_PORT})"
        )

        parser.add_argument(
            "-f", "--forwarder",
            type=self._parse_forwarder,
            default=f"{DEFAULT_FORWARDER_HOST}:{DEFAULT_FORWARDER_IP}",
            required=False,
            help=f"Старший сервер в формате ip:port, ({DEFAULT_FORWARDER_HOST}:{DEFAULT_FORWARDER_IP} по умолчанию)"
        )

        parser.add_argument(
            "-h", "--help",
            action="help",
            help="Показать справку и выйти"
        )

        return parser

    def parse(self):
        args = self.parser.parse_args()
        return {
            self.LISTEN_PORT_KEY: args.port,
            self.FORWARD_HOST_KEY: args.forwarder[0],
            self.FORWARD_PORT_KEY: args.forwarder[1],
        }
