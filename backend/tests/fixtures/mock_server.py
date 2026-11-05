"""A small threaded HTTP server used as a deterministic scan target in tests.

Serves a few routes that exercise the engine and crawler: an HTML page with
links/forms/scripts, an inline-JS API reference, a JSON API endpoint, a
redirect, and a large body for the truncation test.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDEX_HTML = """<!doctype html>
<html><head>
  <script src="/static/app.js"></script>
  <script>
    const baseURL = "/api";
    fetch("/api/users").then(r => r.json());
    axios.get("/api/orders");
  </script>
</head>
<body>
  <a href="/about">About</a>
  <a href="/page2">Page 2</a>
  <a href="https://external.example.org/x">External</a>
  <form action="/search" method="get"></form>
</body></html>"""

PAGE2_HTML = '<html><body><a href="/deep">Deep</a></body></html>'
ABOUT_HTML = "<html><body>About us</body></html>"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _send(self, code=200, body=b"", ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, INDEX_HTML.encode())
        elif path == "/about":
            self._send(200, ABOUT_HTML.encode())
        elif path == "/page2":
            self._send(200, PAGE2_HTML.encode())
        elif path == "/deep":
            self._send(200, b"<html><body>deep</body></html>")
        elif path == "/api/users":
            self._send(200, b'{"users":[]}', "application/json")
        elif path == "/api/orders":
            self._send(200, b'{"orders":[]}', "application/json")
        elif path == "/static/app.js":
            self._send(200, b'const x = fetch("/api/hidden");', "application/javascript")
        elif path == "/.env":
            self._send(200, b"SECRET_KEY=abc123\nDB_PASSWORD=pw", "text/plain")
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/about")
            self.end_headers()
        elif path == "/big":
            self._send(200, b"A" * (6_000_000), "text/plain")
        else:
            self._send(404, b"not found")


@contextmanager
def mock_server():
    """Start the mock server on a free port; yield its base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
