import threading
import requests
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

# [certificate_server, challenge_server, dns_communication_server]
shutdown_ports = [5001, 5002, 5004]

"""
This HTTP server communicates with the certificate_server, challenge_server and dns_communication_server to inform them 
when the test is complete. That way, all servers can shutdown gracefully.
"""
class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def shutdown(self):
        r = requests.get('https://' + str(record) + ':' + str(shutdown_ports[0]) + '/shutdown', verify=False)
        r = requests.get('http://' + str(record) + ':' + str(shutdown_ports[1]) + '/shutdown')
        r = requests.get('http://' + str(record) + ':' + str(shutdown_ports[2]) + '/shutdown')
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    def do_GET(self):
        print('***GET***')
        self._set_headers()
        self.wfile.write('Shutting down'.encode())
        if self.path == '/shutdown':
            self.shutdown()

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        print('***POST***')
        # Doesn't do anything with posted data
        self._set_headers()
        self.wfile.write(''.encode())


def run(server_class=HTTPServer, handler_class=S, addr='localhost', port=5003):
    global httpd
    server_address = (addr, port)
    httpd = server_class(server_address, handler_class)

    print(f"Starting httpd server on {addr}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    global record
    if len(sys.argv) == 1:
        record = 'localhost'
        run()
    else:
        record = sys.argv[1]
        run(addr=record)
