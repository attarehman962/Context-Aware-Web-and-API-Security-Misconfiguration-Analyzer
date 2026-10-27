"""Tests for the 58-check catalog/registry and representative detections."""
from __future__ import annotations

from app.core.body_classifier import classify_body
from app.core.checks import REGISTRY, CheckContext, run_checks
from app.core.checks.catalog import CATALOG
from app.core.engine import HttpResult


def _ctx(headers=None, body="", status=200, path="/", url=None, ctype="text/html",
         **kw) -> CheckContext:
    res = HttpResult(
        requested_url=url or f"https://t.example{path}",
        final_url=url or f"https://t.example{path}",
        method="GET",
        status_code=status,
        headers=headers or {},
        body=body,
        content_type=ctype,
    )
    return CheckContext(url=url or f"https://t.example{path}", path=path, result=res, **kw)


def test_catalog_has_58_rules_with_complete_metadata():
    assert len(CATALOG) == 58
    ids = list(CATALOG.keys())
    assert len(ids) == len(set(ids))  # unique rule_ids
    for meta in CATALOG.values():
        assert meta.cvss_vector.startswith("CVSS:3.1/")
        assert 0.0 < meta.base_score <= 10.0
        assert meta.impact and meta.recommendation


def test_every_catalog_rule_has_exactly_one_implementation():
    # A rule is either a legacy @rule function or has moved to the spec registry
    # (docs/adding-a-check.md), never both: both would report it twice.
    from app.core.checks.registry import CHECKS, load_implementations

    load_implementations()
    moved = set(CATALOG) & set(CHECKS)
    assert "HDR-001" in moved
    legacy_ids = {fn.__name__.split("_")[0].upper() + "-" + fn.__name__.split("_")[1]
                  for fn in REGISTRY}
    assert not legacy_ids & moved
    assert len(REGISTRY) + len(moved) == 58


def test_missing_headers_fire():
    # HDR-001..008 are spec-registry checks now (tests/checks/); the legacy
    # header rules left are HDR-009..012.
    ctx = _ctx(headers={}, body="<html></html>")
    ids = {f.rule_id for f in run_checks(ctx)}
    assert {"HDR-009", "HDR-010"} <= ids


def test_full_headers_suppress_findings():
    ctx = _ctx(headers={
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    })
    ids = {f.rule_id for f in run_checks(ctx)}
    for rid in ("HDR-009", "HDR-010"):
        assert rid not in ids


def test_short_session_cookie_value():
    # CKI-001..003 (flags) are spec-registry checks now (tests/checks/).
    ctx = _ctx(body="")
    ctx.result.set_cookie_headers = ["sessionid=abc; Path=/"]
    ids = {f.rule_id for f in run_checks(ctx)}
    assert "CKI-006" in ids


def test_cors_wildcard_origin():
    # COR-002/COR-003 are spec-registry checks now (tests/checks/).
    ctx = _ctx()
    ctx.cors_acao = "*"
    assert "COR-001" in {f.rule_id for f in run_checks(ctx)}


def test_env_exposure_and_secrets():
    body = "SECRET_KEY=abc123\nDB_PASSWORD=hunter2000"
    ctx = _ctx(body=body, path="/.env", ctype="text/plain")
    ctx.body_class = classify_body(body)
    ids = {f.rule_id for f in run_checks(ctx)}
    assert "INF-003" in ids   # .env exposed
    assert "API-013" in ids   # secrets in response


def test_moved_rules_no_longer_run_as_legacy():
    ctx = _ctx(headers={}, body="Traceback (most recent call last): ...")
    ctx.result.set_cookie_headers = ["sessionid=abc; Path=/"]
    ids = {f.rule_id for f in run_checks(ctx)}
    assert not ids & {"HDR-002", "CKI-001", "COR-002", "API-004", "INF-002", "TLS-005"}


def test_limitation_marked_on_blackbox_checks():
    # BOLA fires on a numeric id in an /api path and must carry a limitation.
    ctx = _ctx(path="/api/users/123", ctype="application/json", body='{"id":123}')
    bola = [f for f in run_checks(ctx) if f.rule_id == "API-006"]
    assert bola and bola[0].limitation
