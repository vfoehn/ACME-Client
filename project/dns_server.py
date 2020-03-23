from __future__ import print_function
import multiprocessing
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

import binascii, socket, struct, threading, time, random

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

from dnslib import DNSRecord, DNSError, QTYPE, RR

ACME_PREFIX = "_acme-challenge"
KEY_AUTHORIZATION = "dummy.dummy"


"""
This file contains the implementation of a DNS server. The ACME client can upload its DNS challenge to this DNS server.
In a further step, the ACME server can then request to DNS challenge.
"""
class BaseResolver(object):

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname)
        if qname[:len(ACME_PREFIX)] == ACME_PREFIX:  # ACME dns-01 verification
            reply.add_answer(*RR.fromZone(qname + " 300 IN TXT " + str(shared_dict['key_authorization'])))
        else:
            reply.add_answer(*RR.fromZone(qname + " 300 A " + str(IP_ADDRESS)))
        reply.header.rcode = 0
        #print("reply:\n" + str(reply))
        return reply


class DNSHandler(socketserver.BaseRequestHandler):
    """
        Handler for socketserver. Transparently handles both TCP/UDP requests
        (TCP requests have length prepended) and hands off lookup to resolver
        instance specified in <SocketServer>.resolver
    """

    udplen = 0  # Max udp packet length (0 = ignore)

    def send_ack_to_acme_client(self, data):
        print('received message:', data)
        remote_port = str(data).split(' ')[4]
        remote_port = remote_port[:len(remote_port) - 1]

        local_port = 5005
        success = False
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        while not success:
            try:
                sock.bind((IP_ADDRESS, local_port))
                success = True
            except:
                print('Port ' + str(local_port) + ' is already taken.')
                local_port = random.randint(5005, 6000)

        sock.sendto('ACK'.encode(), (IP_ADDRESS, int(remote_port)))

    def handle(self):
        print('\n\n')
        if self.server.socket_type == socket.SOCK_STREAM:
            self.protocol = 'tcp'
            data = self.request.recv(8192)
            print("TCP data: " + data)
            length = struct.unpack("!H", bytes(data[:2]))[0]
            while len(data) - 2 < length:
                data += self.request.recv(8192)
            data = data[2:]
        else:
            self.protocol = 'udp'
            data, connection = self.request

        self.server.logger.log_recv(self, data)

        try:
            rdata = self.get_reply(data)
            self.server.logger.log_send(self, rdata)

            if self.protocol == 'tcp':
                rdata = struct.pack("!H", len(rdata)) + rdata
                self.request.sendall(rdata)
            else:
                connection.sendto(rdata, self.client_address)

        except DNSError as e:
            self.server.logger.log_error(self, e)

    def get_reply(self, data):
        request = DNSRecord.parse(data)
        self.server.logger.log_request(self, request)

        resolver = self.server.resolver
        reply = resolver.resolve(request, self)
        self.server.logger.log_reply(self, reply)

        if self.protocol == 'udp':
            rdata = reply.pack()
            if self.udplen and len(rdata) > self.udplen:
                truncated_reply = reply.truncate()
                rdata = truncated_reply.pack()
                self.server.logger.log_truncated(self, truncated_reply)
        else:
            rdata = reply.pack()

        return rdata


class DNSLogger:
    """
        The class provides a default set of logging functions for the various
        stages of the request handled by a DNSServer instance which are
        enabled/disabled by flags in the 'log' class variable.

        To customise logging create an object which implements the DNSLogger
        interface and pass instance to DNSServer.

        The methods which the logger instance must implement are:

            log_recv          - Raw packet received
            log_send          - Raw packet sent
            log_request       - DNS Request
            log_reply         - DNS Response
            log_truncated     - Truncated
            log_error         - Decoding error
            log_data          - Dump full request/response
    """

    def __init__(self, log="", prefix=True):
        """
            Selectively enable log hooks depending on log argument
            (comma separated list of hooks to enable/disable)

            - If empty enable default log hooks
            - If entry starts with '+' (eg. +send,+recv) enable hook
            - If entry starts with '-' (eg. -data) disable hook
            - If entry doesn't start with +/- replace defaults

            Prefix argument enables/disables log prefix
        """
        default = ["request", "reply", "truncated", "error"]
        log = log.split(",") if log else []
        enabled = set([s for s in log if s[0] not in '+-'] or default)
        [enabled.add(l[1:]) for l in log if l.startswith('+')]
        [enabled.discard(l[1:]) for l in log if l.startswith('-')]
        for l in ['log_recv', 'log_send', 'log_request', 'log_reply',
                  'log_truncated', 'log_error', 'log_data']:
            if l[4:] not in enabled:
                setattr(self, l, self.log_pass)
        self.prefix = prefix

    def log_pass(self, *args):
        pass

    def log_prefix(self, handler):
        if self.prefix:
            return "%s [%s:%s] " % (time.strftime("%Y-%M-%d %X"),
                                    handler.__class__.__name__,
                                    handler.server.resolver.__class__.__name__)
        else:
            return ""

    def log_recv(self, handler, data):
        print("%sReceived: [%s:%d] (%s) <%d> : %s" % (
            self.log_prefix(handler),
            handler.client_address[0],
            handler.client_address[1],
            handler.protocol,
            len(data),
            binascii.hexlify(data)))

    def log_send(self, handler, data):
        print("%sSent: [%s:%d] (%s) <%d> : %s" % (
            self.log_prefix(handler),
            handler.client_address[0],
            handler.client_address[1],
            handler.protocol,
            len(data),
            binascii.hexlify(data)))

    def log_request(self, handler, request):
        print("%sRequest: [%s:%d] (%s) / '%s' (%s)" % (
            self.log_prefix(handler),
            handler.client_address[0],
            handler.client_address[1],
            handler.protocol,
            request.q.qname,
            QTYPE[request.q.qtype]))
        self.log_data(request)

    def log_reply(self, handler, reply):
        print("%sReply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
            self.log_prefix(handler),
            handler.client_address[0],
            handler.client_address[1],
            handler.protocol,
            reply.q.qname,
            QTYPE[reply.q.qtype],
            ",".join([QTYPE[a.rtype] for a in reply.rr])))
        self.log_data(reply)

    def log_truncated(self, handler, reply):
        print("%sTruncated Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
            self.log_prefix(handler),
            handler.client_address[0],
            handler.client_address[1],
            handler.protocol,
            reply.q.qname,
            QTYPE[reply.q.qtype],
            ",".join([QTYPE[a.rtype] for a in reply.rr])))
        self.log_data(reply)

    def log_error(self, handler, e):
        print("%sInvalid Request: [%s:%d] (%s) :: %s" % (
            self.log_prefix(handler),
            handler.client_address[0],
            handler.client_address[1],
            handler.protocol,
            e))

    def log_data(self, dnsobj):
        print("\n", dnsobj.toZone("    "), "\n", sep="")


class UDPServer(socketserver.UDPServer):
    allow_reuse_address = True


class TCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class DNSServer(object):
    """
        Convenience wrapper for socketserver instance allowing
        either UDP/TCP server to be started in blocking more
        or as a background thread.

        Processing is delegated to custom resolver (instance) and
        optionally custom logger (instance), handler (class), and
        server (class)

        In most cases only a custom resolver instance is required
        (and possibly logger)
    """

    def __init__(self, resolver,
                 address="",
                 port=53,
                 tcp=False,
                 logger=None,
                 handler=DNSHandler,
                 server=None):
        """
            resolver:   resolver instance
            address:    listen address (default: "")
            port:       listen port (default: 53)
            tcp:        UDP (false) / TCP (true) (default: False)
            logger:     logger instance (default: DNSLogger)
            handler:    handler class (default: DNSHandler)
            server:     socketserver class (default: UDPServer/TCPServer)
        """
        if not server:
            if tcp:
                server = TCPServer
            else:
                server = UDPServer
        self.server = server((address, port), handler)
        self.server.resolver = resolver
        self.server.logger = logger or DNSLogger()

    def start(self, shared_dict):
        self.server.serve_forever()

    def start_thread(self):
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.server.shutdown()

    def isAlive(self):
        return self.thread.isAlive()


class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def shutdown(self):
        dns_server_proc.terminate()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    def do_GET(self):
        print('***GET***')
        headers = self.headers
        file_path = self.path
        if file_path == '/shutdown':
            self._set_headers()
            self.wfile.write('Shutting down'.encode())
            self.shutdown()
        else:
            self._set_headers()
            with open('./' + file_path, 'rb') as file:
                self.wfile.write(file.read())

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        global shared_dict
        print('***POST***')
        # Doesn't do anything with posted data
        file_path = self.path
        self._set_headers()
        if file_path == '/key_authorization':
            raw_data = (self.rfile.read(int(self.headers['content-length']))).decode('utf-8')
            print(raw_data)
            shared_dict['key_authorization'] = raw_data
        elif file_path == '/remove_key_authorization':
            shared_dict['key_authorization'] = ''
        self.wfile.write(''.encode())


def run_communication_server(server_class=HTTPServer, handler_class=S, addr='localhost', port=5004):
    global httpd
    server_address = (addr, port)
    httpd = server_class(server_address, handler_class)

    print(f"Starting httpd server on {addr}:{port}")
    httpd.serve_forever()


def main():
    global dns_server_proc, shared_dict
    resolver = BaseResolver()
    logger = DNSLogger(prefix=False)
    server = DNSServer(resolver, port=10053, address=IP_ADDRESS, logger=logger)

    manager = multiprocessing.Manager()
    shared_dict = manager.dict()
    shared_dict['key_authorization'] = 'dummy.dummy'

    dns_server_proc = multiprocessing.Process(target=server.start, args=[shared_dict])
    dns_server_proc.start()

    run_communication_server(addr=IP_ADDRESS)


if __name__ == "__main__":
    try:
        global IP_ADDRESS
        if len(sys.argv) >= 2:
            IP_ADDRESS = sys.argv[1]
        else:
            IP_ADDRESS = 'localhost'
        main()
    except KeyboardInterrupt:
        print("Keyboard interrupted.")
        try:
            dns_server_proc.terminate()
        except:
            pass
