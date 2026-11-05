"""Fixtures for the CAWASMA self security review (Asim Prompt 9).

``logging_target`` is a local HTTP server that records every request it
receives (method, Host header, path, headers): the scanner's traffic as the
target sees it. It answers for two names, ``target.test`` (in scope) and
``other.test`` (out of scope), so a request that leaves the target host shows
up in the log with ``Host: other.test``. This is stricter than a forward
proxy: the engine ignores proxy settings on purpose (``trust_env=False``, so a
proxy can't bypass the SSRF pinning), and the target sees everything,
including requests a proxy would never be asked to forward.

``dns`` maps names to addresses through a monkeypatched ``getaddrinfo``.
No test ever resolves or contacts a real internal host.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

# Fake secrets the target serves. None may appear unredacted anywhere.
# Each one is assembled at run time, so no secret-shaped literal sits in the repo.
JWT = (
    "eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0."
    "c2lnbmF0dXJlLWZha2UtZm9yLXRlc3Rz"
)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRETS = {
    "jwt": JWT,
    "aws_access_key": AWS_KEY,
    "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "db_password": "SuperSecret-DB-Pass-123",
    "json_password": "hunter2-json-secret",
    "api_key": "cawasma-fake-apikey-7f3a9c2e1b5d",
    "session_cookie": "SESSIONVALUE-abc123def456ghi789",
    "private_key_body": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7FAKE",
    "card": "4111111111111111",
}

ENV_FILE = (
    f"DB_PASSWORD={SECRETS['db_password']}\n"
    f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"
    f"AWS_SECRET_ACCESS_KEY={SECRETS['aws_secret']}\n"
)
API_USERS = (
    '{"users": [{"id": 1, "email": "alice@example.com", '
    f'"password": "{SECRETS["json_password"]}", "card": "{SECRETS["card"]}", '
    f'"token": "{JWT}", "api_key": "{SECRETS["api_key"]}", '
    '"internal_host": "10.20.30.40"}]}'
)
PRIVATE_KEY = (
    "-----BEGIN "
    + "RSA PRIVATE KEY-----\n"
    + SECRETS["private_key_body"]
    + "\n-----END RSA PRIVATE KEY-----\n"
)


def known_issue(issue: str, owner: str, what: str):
    """A test that fails today because of an open issue in docs/security-review.md.

    Strict: once the owner fixes it the test passes (XPASS), which fails the run,
    so the marker must be removed and the review's status updated.
    """
    return pytest.mark.xfail(strict=True, reason=f"{issue} ({owner}): {what}")


@dataclass
class Logged:
    method: str
    host: str
    path: str
    headers: dict[str, str]


@dataclass
class Target:
    port: int
    log: list[Logged] = field(default_factory=list)

    @property
    def url(self) -> str:
        return f"http://target.test:{self.port}/"

    def methods(self) -> set[str]:
        return {r.method for r in self.log}

    def hosts(self) -> set[str]:
        return {r.host.split(":")[0].lower() for r in self.log}


def _index(port: int) -> str:
    other = f"http://other.test:{port}"
    return f"""<!doctype html><html><head>
<script src="/static/app.js"></script>
<script>
  fetch("/api/users");
  fetch("{other}/api/stolen");
  const cdn = "{other}/cdn/lib.js";
</script></head><body>
<a href="/about">About</a>
<a href="/redirect-out">Partner</a>
<a href="/redirect-in">Home</a>
<a href="/.env">Config</a>
<a href="{other}/offsite">Offsite</a>
<iframe src="{other}/frame"></iframe>
<img src="{other}/pixel.gif">
<form action="/login" method="post"><input name="u"></form>
<form action="{other}/collect" method="get"></form>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    target: Target

    def log_message(self, *args: object) -> None:
        pass

    def _record(self) -> None:
        self.target.log.append(
            Logged(
                self.command,
                self.headers.get("Host", ""),
                self.path,
                {k.lower(): v for k, v in self.headers.items()},
            )
        )

    def _send(
        self,
        code: int,
        body: str = "",
        ctype: str = "text/html",
        extra: dict[str, str] | None = None,
    ) -> None:
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _route(self) -> None:
        self._record()
        host = self.headers.get("Host", "").split(":")[0].lower()
        path = self.path.split("?")[0]
        port = self.target.port
        if host != "target.test":
            self._send(200, "out of scope")  # logged; must never happen
        elif path == "/":
            self._send(
                200,
                _index(port),
                extra={
                    "Set-Cookie": f"sessionid={SECRETS['session_cookie']}; Path=/",
                    "X-Debug-Token": SECRETS["api_key"],
                    "Server": "Apache/2.4.1 (Unix)",
                    "Access-Control-Allow-Origin": "*",
                },
            )
        elif path == "/about":
            self._send(200, "<html><body>About</body></html>")
        elif path == "/redirect-out":
            self._send(302, extra={"Location": f"http://other.test:{port}/landing"})
        elif path == "/redirect-in":
            self._send(302, extra={"Location": "/about"})
        elif path == "/api/users":
            self._send(200, API_USERS, "application/json")
        elif path == "/.env":
            self._send(200, ENV_FILE, "text/plain")
        elif path == "/static/app.js":
            self._send(
                200,
                'fetch("/api/orders"); const k = "' + PRIVATE_KEY.replace("\n", "\\n") + '";',
                "application/javascript",
            )
        elif path == "/api/orders":
            self._send(
                200,
                '{"orders": [], "debug": "Authorization: Bearer ' + JWT + '"}',
                "application/json",
            )
        else:
            self._send(404, "not found")

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _route

    def do_TRACE(self) -> None:
        self._route()


@pytest.fixture
def dns(monkeypatch):
    """Resolve names from a table; anything else fails to resolve (no real DNS)."""
    table: dict[str, list[str]] = {}

    def getaddrinfo(host, port, *args, **kwargs):
        name = str(host).rstrip(".").lower()
        if name not in table:
            raise socket.gaierror(socket.EAI_NONAME, f"{name}: stubbed, unknown")
        out = []
        for ip in table[name]:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            addr = (ip, port or 443, 0, 0) if fam == socket.AF_INET6 else (ip, port or 443)
            out.append((fam, socket.SOCK_STREAM, 6, "", addr))
        return out

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return table


@pytest.fixture
def logging_target(dns) -> Iterator[Target]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    target = Target(port=server.server_address[1])
    _Handler.target = target
    dns["target.test"] = ["127.0.0.1"]
    dns["other.test"] = ["127.0.0.1"]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield target
    finally:
        server.shutdown()
        server.server_close()
