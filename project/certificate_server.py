from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import threading
import sys

"""
We install an X.509 certificate on this server so it is able to support HTTPS connections.
Additionally, the server returns the certificate as a PEM file when requested by a GET request.
"""
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def shutdown(self):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    def do_GET(self):
        print('***GET***')
        self._set_headers()
        if self.path == '/shutdown':
            self.wfile.write('Shutting down'.encode())
            self.shutdown()
        with open('keys/chained_cert.pem', 'r') as f:
            self.wfile.write(f.read().encode())

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        print('***POST***')
        # Doesn't do anything with posted data
        self._set_headers()
        self.wfile.write(''.encode())


def run(addr='localhost'):
    global httpd
    httpd = HTTPServer((addr, 5001), SimpleHTTPRequestHandler)
    print('Inside certificate server')
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   keyfile="keys/private_key.pem",
                                   certfile='keys/chained_cert.pem', server_side=True)

    httpd.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run()
    else:
        run(addr=sys.argv[1])
