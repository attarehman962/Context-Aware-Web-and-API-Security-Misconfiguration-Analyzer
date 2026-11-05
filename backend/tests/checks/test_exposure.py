"""API-001, API-003, INF-003, INF-004, INF-005: the specs that use applies_to and
artifact (checks.yaml, proposed 2026-11-05). Each check fires on a vulnerable
response and stays silent on the close cases its spec excludes."""

from __future__ import annotations

import json

from app.core.checks.registry import SoftNotFound, SpecContext
from app.core.contracts import SensitivityClass
from tests.checks.helpers import assert_fires, assert_no_fire, endpoint, response

SITE = "https://shop.example.com"
ACTIVE = SpecContext(sensitivity=SensitivityClass.LOW)
PASSIVE = SpecContext(sensitivity=SensitivityClass.LOW, passive=True)
JSON = "application/json"


def _soft_404(status: int = 404, body: str = "<h1>Not found: /cawasma-1a2b</h1>"):
    return SoftNotFound("/cawasma-1a2b", status, body)


# API-001: authentication endpoints without rate-limit headers


def test_api001_fires_on_an_auth_endpoint_without_rate_limit_headers():
    auth = SpecContext(sensitivity=SensitivityClass.HIGH, families=frozenset({"authentication"}))
    assert_fires("API-001", response(SITE + "/login"), ctx=auth)
    # A POST route whose path names an auth step counts even if the classifier
    # put it in another family.
    ep = endpoint(SITE + "/api/v1/token", method="POST")
    assert_fires("API-001", response(SITE + "/api/v1/token"), ep, ctx=ACTIVE)


def test_api001_no_fire():
    auth = SpecContext(families=frozenset({"authentication"}))
    for header in ("RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"):
        assert_no_fire("API-001", response(SITE + "/login", headers={header: "10"}), ctx=auth)
    # Not an auth endpoint: no family, and the auth-looking path is only a GET.
    assert_no_fire("API-001", response(SITE + "/products"), ctx=ACTIVE)
    assert_no_fire("API-001", response(SITE + "/token-info"), ctx=ACTIVE)


# API-003: sensitive data to a request without credentials


def test_api003_fires_on_sensitive_json_without_credentials():
    body = json.dumps([{"id": 1, "email": "a@example.com"}])
    for cls in (SensitivityClass.HIGH, SensitivityClass.CRITICAL):
        found = assert_fires(
            "API-003",
            response(SITE + "/api/v1/users", body=body, content_type=JSON),
            ctx=SpecContext(sensitivity=cls),
        )
        assert "1 items" in found[0].evidence["text"]


def test_api003_no_fire():
    high = SpecContext(sensitivity=SensitivityClass.HIGH)
    users = SITE + "/api/v1/users"
    data = json.dumps({"users": [1]})
    # LOW / MEDIUM endpoints are not "sensitive".
    for cls in (SensitivityClass.LOW, SensitivityClass.MEDIUM):
        assert_no_fire(
            "API-003",
            response(users, body=data, content_type=JSON),
            ctx=SpecContext(sensitivity=cls),
        )
    # Credentials were sent; not 2xx; empty JSON; an HTML login page.
    assert_no_fire(
        "API-003",
        response(users, body=data, content_type=JSON, request_headers={"Cookie": "s=1"}),
        ctx=high,
    )
    assert_no_fire("API-003", response(users, status=401, body=data), ctx=high)
    assert_no_fire("API-003", response(users, body="[]", content_type=JSON), ctx=high)
    assert_no_fire("API-003", response(users, body="<form>Sign in</form>"), ctx=high)


def test_api003_no_fire_when_redirected_to_a_login_page():
    resp = response(SITE + "/api/v1/users", body='{"error": "login"}', content_type=JSON)
    resp.final_url = SITE + "/auth/login?next=/api/v1/users"
    assert_no_fire("API-003", resp, ctx=SpecContext(sensitivity=SensitivityClass.HIGH))


# INF-003: .env


def test_inf003_fires_on_an_env_file_and_stores_names_only():
    body = "APP_ENV=production\nDB_PASSWORD=cawasma-fake-value\n"
    for path in ("/.env", "/app/.env.local"):
        found = assert_fires(
            "INF-003", response(SITE + path, body=body, content_type="text/plain"), ctx=ACTIVE
        )
        assert found[0].evidence["variables"] == ["APP_ENV", "DB_PASSWORD"]
        assert "cawasma-fake-value" not in json.dumps(found[0].evidence)


def test_inf003_no_fire():
    env = "DB_PASSWORD=cawasma-fake-value\n"
    # Not an artifact path; an HTML page; no KEY= line; not 200.
    assert_no_fire("INF-003", response(SITE + "/.envrc", body=env), ctx=ACTIVE)
    assert_no_fire("INF-003", response(SITE + "/.env", body="<html>" + env), ctx=ACTIVE)
    assert_no_fire(
        "INF-003", response(SITE + "/.env", body="# empty\n", content_type="text/plain"), ctx=ACTIVE
    )
    assert_no_fire(
        "INF-003",
        response(SITE + "/.env", status=403, body=env, content_type="text/plain"),
        ctx=ACTIVE,
    )


# INF-004: .git


def test_inf004_fires_on_git_head_and_config():
    plain = "text/plain"
    assert_fires(
        "INF-004",
        response(SITE + "/.git/HEAD", body="ref: refs/heads/main\n", content_type=plain),
        ctx=ACTIVE,
    )
    assert_fires(
        "INF-004",
        response(
            SITE + "/.git/HEAD", body="0123456789abcdef" * 2 + "01234567\n", content_type=plain
        ),
        ctx=ACTIVE,
    )
    assert_fires(
        "INF-004",
        response(
            SITE + "/.git/config",
            body="[core]\n\trepositoryformatversion = 0\n",
            content_type=plain,
        ),
        ctx=ACTIVE,
    )


def test_inf004_no_fire_on_a_404_page_that_quotes_git_head():
    """The old false positive: a 404 page mentioning .git/HEAD."""
    page = "<html><p>Not found: /.git/HEAD</p><p>ref: refs/heads/main</p></html>"
    assert_no_fire("INF-004", response(SITE + "/.git/HEAD", status=404, body=page), ctx=ACTIVE)
    assert_no_fire("INF-004", response(SITE + "/.git/HEAD", body=page), ctx=ACTIVE)  # 200, HTML
    assert_no_fire(
        "INF-004",
        response(SITE + "/.git/HEAD", body="hello", content_type="text/plain"),
        ctx=ACTIVE,
    )


# INF-005: backups and archives


def test_inf005_fires_on_a_backup_or_archive():
    zipped = response(SITE + "/backup.zip", content_type="application/zip")
    zipped.content_length = 2048  # binary: the decoded body is ""
    assert_fires("INF-005", zipped, ctx=ACTIVE)
    assert_fires(
        "INF-005",
        response(SITE + "/config.php.bak", body="<?php $db = 'x';", content_type="text/plain"),
        ctx=ACTIVE,
    )
    assert_fires(
        "INF-005",
        response(SITE + "/notes.txt~", body="draft", content_type="text/plain"),
        ctx=ACTIVE,
    )


def test_inf005_no_fire():
    assert_no_fire("INF-005", response(SITE + "/index.php", body="x"), ctx=ACTIVE)  # suffix
    assert_no_fire(
        "INF-005", response(SITE + "/db.sql", body="", content_type="text/plain"), ctx=ACTIVE
    )  # empty
    assert_no_fire("INF-005", response(SITE + "/db.sql", status=404, body="gone"), ctx=ACTIVE)


# Shared rules for INF-003/004/005


def test_artifacts_never_fire_on_the_soft_404_page():
    """A catch-all site answers every path with the same 200 page."""
    shell = '<div id="app"></div>'
    ctx = SpecContext(soft_404=_soft_404(200, shell))
    assert_no_fire("INF-005", response(SITE + "/backup.zip", body=shell), ctx=ctx)
    assert_no_fire(
        "INF-003",
        response(SITE + "/.env", body="A=1\n" + shell, content_type="text/plain"),
        ctx=SpecContext(soft_404=_soft_404(200, "A=1\n" + shell)),
    )
    # A 404 page that echoes the path it was asked for still counts as the baseline.
    echo = _soft_404(200, "Not found: /cawasma-1a2b")
    assert_no_fire(
        "INF-005",
        response(SITE + "/site.tar.gz", body="Not found: /site.tar.gz"),
        ctx=SpecContext(soft_404=echo),
    )
    # Something else than the baseline does fire.
    assert_fires(
        "INF-005",
        response(SITE + "/site.tar.gz", body="real archive bytes"),
        ctx=SpecContext(soft_404=echo),
    )


def test_artifacts_are_disabled_in_passive_mode():
    env = response(
        SITE + "/.env", body="DB_PASSWORD=cawasma-fake-value\n", content_type="text/plain"
    )
    git = response(SITE + "/.git/HEAD", body="ref: refs/heads/main\n", content_type="text/plain")
    bak = response(SITE + "/db.sql", body="CREATE TABLE users;", content_type="text/plain")
    for check_id, resp in (("INF-003", env), ("INF-004", git), ("INF-005", bak)):
        assert_fires(check_id, resp, ctx=ACTIVE)
        assert_no_fire(check_id, resp, ctx=PASSIVE)
        assert_no_fire(check_id, resp, ctx=None)  # host-level runs have no context
