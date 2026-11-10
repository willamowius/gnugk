"""A small HTTP server in a test host's namespace, for GnuGk's HTTP modules (HttpPasswordAuth, http routing,
HttpAcct)."""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import netns, topology


class HttpServer:
    """answers every request with responder(request) -> (status, body), default 200 with an empty body;
    records the requests as dicts with method, path, query (parsed), body; delay: seconds to wait before
    answering (a slow server)"""

    def __init__(self, host="pub3", port=8080, responder=None, delay=0):
        self.host, self.port, self.delay = host, port, delay
        self.responder = responder or (lambda request: (200, ""))
        self.requests = []
        self._lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode(errors="replace") if length else ""
                url = urlparse(self.path)
                request = {"method": self.command, "path": url.path, "query": parse_qs(url.query),
                           "body": body, "headers": dict(self.headers)}
                with server._lock:
                    server.requests.append(request)
                if server.delay:
                    time.sleep(server.delay)
                status, text = server.responder(request)
                data = text.encode()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    pass

            do_GET = do_POST = _handle

            def log_message(self, *args):
                pass

        with netns.entered(host):
            self.httpd = ThreadingHTTPServer((topology.HOST_IPS[host], port), Handler)
        self.httpd.daemon_threads = True
        self.url = "http://%s:%d" % (topology.HOST_IPS[host], port)
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    def paths(self):
        with self._lock:
            return [r["path"] for r in self.requests]
