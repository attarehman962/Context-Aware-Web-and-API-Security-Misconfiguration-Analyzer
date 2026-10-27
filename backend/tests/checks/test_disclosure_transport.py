"""API-004, INF-002, INF-007 (spec/disclosure.py) and TLS-005 (spec/transport.py)."""
from __future__ import annotations

import pytest

from tests.checks.helpers import assert_fires, assert_no_fire, response

PY_TRACE = ('Traceback (most recent call last):\n  File "/app/views.py", line 4, in get\n'
            "KeyError: 'id'")
JAVA_TRACE = "java.lang.NullPointerException\n\tat com.shop.A.b(A.java:88)\n"
NODE_TRACE = "Error: x\n    at load (/app/orders.js:12:5)\n    at next (/app/router.js:9:3)\n"


@pytest.mark.parametrize("body", [PY_TRACE, JAVA_TRACE, NODE_TRACE,
                                  "System.NullReferenceException: Object reference"])
def test_api004_fires_on_a_stack_trace(body):
    [f] = assert_fires("API-004", response(status=500, body=body))
    assert f.evidence["excerpt"]


@pytest.mark.parametrize("body", ["<p>Something went wrong.</p>",
                                  "A traceback shows where errors happen.",
                                  "    at home (sometimes)"])
def test_api004_no_fire_on_generic_errors(body):
    assert_no_fire("API-004", response(status=500, body=body))


def test_api004_excerpt_is_redacted():
    body = PY_TRACE + "\nDB_PASSWORD=hunter2secret"
    [f] = assert_fires("API-004", response(status=500, body=body))
    assert "hunter2secret" not in f.evidence["excerpt"]


@pytest.mark.parametrize("body", ["<html><title>Index of /config</title>",
                                  "<h1>Index of /docs</h1>", "<a href='/'>Parent Directory</a>"])
def test_inf002_fires_on_a_directory_listing(body):
    assert_fires("INF-002", response(body=body))


@pytest.mark.parametrize("body", ["<h1>Our product index</h1>", "<title>Docs</title>"])
def test_inf002_no_fire_on_ordinary_pages(body):
    assert_no_fire("INF-002", response(body=body))


@pytest.mark.parametrize("resp", [
    response(status=500, body="<h1>Exception details</h1>"),
    response(body="Running in debug mode"),
    response(status=500, body="Internal Server Error: SQL error near 'x' in query"),
    response(headers={"X-Debug-Token": "a1b2c3"}),
])
def test_inf007_fires_on_verbose_errors(resp):
    assert_fires("INF-007", resp)


@pytest.mark.parametrize("body", ["<h1>500 Internal Server Error</h1>", "Debugging tips (docs)"])
def test_inf007_no_fire_on_generic_errors(body):
    assert_no_fire("INF-007", response(status=500, body=body))


def _http_probe(status, location=None):
    headers = {"Location": location} if location else {}
    return response("http://shop.example.com/", status=status, headers=headers)


@pytest.mark.parametrize("status", [200, 403, 404])
def test_tls005_fires_when_http_is_not_redirected(status):
    assert_fires("TLS-005", _http_probe(status))


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_tls005_no_fire_on_a_redirect(status):
    assert_no_fire("TLS-005", _http_probe(status, "https://shop.example.com/"))


def test_tls005_never_judges_an_https_response():
    assert_no_fire("TLS-005", response("https://shop.example.com/", status=200))
