import threading
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

"""
This HTTP server is used to serve the HTTP challenge token. More precisely, the ACME client uploads the challenge token 
to this server. Later on, the ACME server requests the token from this server.
Note: This server does not support TLS because it does not have a valid certificate yet.
"""
class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def shutdown(self):
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
        print('***POST***')
        # Doesn't do anything with posted data
        self._set_headers()
        self.wfile.write(self._html('Received GET').encode())


def run(server_class=HTTPServer, handler_class=S, addr='localhost', port=5002):
    global httpd
    server_address = (addr, port)
    httpd = server_class(server_address, handler_class)

    print(f"Starting httpd server on {addr}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run()
    else:
        run(addr=sys.argv[1])
