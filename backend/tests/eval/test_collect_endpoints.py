"""eval/labels/collect_endpoints.py (review asim-p04 #3, #6)."""
from __future__ import annotations

import csv
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.eval.conftest import load_eval_script

collector = load_eval_script("labels/collect_endpoints.py")

PAGES = {
    "/": '<a href="/users/1">u</a><a href="/users/2">u</a><a href="/about">a</a>'
         '<script src="/main.js"></script><img src="/logo.png"><link href="/site.css">',
    "/main.js": 'fetch("/api/Products/42");const u=`/rest/user/${id}/basket`;'
                'http.get("/identity/api/auth/login");const x="https://cdn.example/api/x";',
    "/about": "<p>about</p>",
    "/users/1": "{}",
    "/users/2": "{}",
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        body = PAGES.get(self.path)
        self.send_response(200 if body is not None else 404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write((body or "").encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _rows(path):
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def test_collects_and_normalises_paths(site, tmp_path):
    out = tmp_path / "raw.csv"
    assert collector.main(["--base-url", f"demo={site}", "--output", str(out)]) == 0
    paths = {r["path"] for r in _rows(out)}
    assert {"/", "/about", "/users/:id"} <= paths
    assert not any(p.startswith("/users/1") for p in paths)  # ID variants de-duplicated


def test_unreachable_target_fails_loudly(site, tmp_path, capsys):
    out = tmp_path / "raw.csv"
    code = collector.main(["--base-url", f"demo={site}", "--base-url", "down=http://127.0.0.1:9",
                           "--output", str(out)])
    assert code == 1
    assert "down: 0 endpoints" in capsys.readouterr().err


def test_unknown_target_name_is_rejected(tmp_path):
    assert collector.main(["no-such-target", "--output", str(tmp_path / "x.csv")]) == 2


@pytest.mark.parametrize("arg", ["demo=file:///etc/passwd", "no-equals-sign"])
def test_base_url_must_be_http(arg, tmp_path):
    assert collector.main(["--base-url", arg, "--output", str(tmp_path / "x.csv")]) == 2


def test_spa_routes_come_from_javascript_and_assets_are_skipped(site, tmp_path):
    out = tmp_path / "raw.csv"
    assert collector.main(["--base-url", f"demo={site}", "--output", str(out)]) == 0
    paths = {r["path"] for r in _rows(out)}
    assert {"/api/Products/:id", "/rest/user/:id/basket", "/identity/api/auth/login"} <= paths
    assert not {"/main.js", "/logo.png", "/site.css"} & paths     # assets aren't endpoints
    assert not any("cdn.example" in p for p in paths)               # off-origin URLs ignored
