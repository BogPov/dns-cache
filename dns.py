from cli.args_parser import CLIArgsParser
from server.udp_server import DNSServer


if __name__ == '__main__':
    parser = CLIArgsParser()
    config = parser.parse()

    LISTEN_PORT = config[CLIArgsParser.LISTEN_PORT_KEY]
    FORWARDER_IP = config[CLIArgsParser.FORWARD_HOST_KEY]
    FORWARDER_PORT = config[CLIArgsParser.FORWARD_PORT_KEY]

    server = DNSServer(LISTEN_PORT, forwarder_host=FORWARDER_IP, forwarder_port=FORWARDER_PORT)
    server.serve()
