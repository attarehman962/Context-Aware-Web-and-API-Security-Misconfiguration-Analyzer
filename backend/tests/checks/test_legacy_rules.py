"""Fire and no-fire tests for the 37 legacy ``@rule`` checks (one test per rule).

Each test gives the rule a context it must report and a close one it must not,
so a rule that fires on everything or on nothing fails.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from app.core.body_classifier import BodyClassification
from app.core.tls import TlsProbe
from app.db.models.enums import ContextClass
from tests.checks.helpers import assert_rule_fires, assert_rule_no_fire, context

API = "https://shop.example.com/api/v1/orders"
JSON = "application/json"


def _tls(**fields) -> TlsProbe:
    return TlsProbe(host="shop.example.com", reachable=True, **fields)


# REST API


def test_api002_trace():
    assert_rule_fires("API-002", context(allowed_methods={"GET", "TRACE"}))
    assert_rule_no_fire("API-002", context(allowed_methods={"GET", "HEAD"}))


def test_api005_privilege_fields():
    assert_rule_fires("API-005", context(API, content_type=JSON, body='{"role": "admin"}'))
    assert_rule_no_fire("API-005", context(API, content_type=JSON, body='{"name": "a"}'))


def test_api006_numeric_object_id():
    assert_rule_fires("API-006", context(API + "/42", content_type=JSON))
    assert_rule_no_fire("API-006", context(API, content_type=JSON))


def test_api007_unversioned_api():
    assert_rule_fires("API-007", context("https://shop.example.com/api/orders"))
    assert_rule_no_fire("API-007", context(API))


def test_api008_deprecation_header():
    assert_rule_fires("API-008", context(API, headers={"Deprecation": "true"}))
    assert_rule_no_fire("API-008", context(API))


def test_api009_many_methods():
    assert_rule_fires("API-009", context(allowed_methods={"GET", "POST", "PUT", "DELETE", "PATCH"}))
    assert_rule_no_fire("API-009", context(allowed_methods={"GET", "HEAD", "OPTIONS"}))


def test_api010_jwt():
    # Built at run time so no JWT-shaped literal sits in the repo (secret scanners).
    token = ".".join(["eyJ" + "a" * 12, "b" * 12, "c" * 12])
    assert_rule_fires("API-010", context(API, body=f'{{"token": "{token}"}}'))
    assert_rule_no_fire("API-010", context(API, body='{"token": "opaque-session-id"}'))


def test_api011_overfetching():
    many = json.dumps({f"field{i}": i for i in range(41)})
    assert_rule_fires("API-011", context(API, content_type=JSON, body=many))
    assert_rule_no_fire(
        "API-011", context(API, content_type=JSON, body=json.dumps({"id": 1, "total": 9}))
    )


def test_api012_graphql_introspection():
    assert_rule_fires("API-012", context(graphql_introspection=True))
    assert_rule_no_fire("API-012", context(body='{"data": {"shop": "ok"}}'))


def test_api013_secrets_in_body():
    assert_rule_fires("API-013", context(body_class=BodyClassification(credentials=True)))
    assert_rule_no_fire("API-013", context(body_class=BodyClassification(pii=True)))


def test_api014_injection_error_reflected():
    assert_rule_fires("API-014", context(injection_error_reflected=True))
    assert_rule_no_fire("API-014", context())


# Auth


def test_aut001_basic_auth():
    assert_rule_fires(
        "AUT-001", context(status=401, headers={"WWW-Authenticate": 'Basic realm="x"'})
    )
    assert_rule_no_fire("AUT-001", context(status=401, headers={"WWW-Authenticate": "Bearer"}))


def test_aut002_admin_reachable():
    assert_rule_fires("AUT-002", context("https://shop.example.com/admin"))
    assert_rule_no_fire("AUT-002", context("https://shop.example.com/badminton"))


def test_aut003_short_reset_token():
    assert_rule_fires("AUT-003", context("https://shop.example.com/reset?token=abc123"))
    assert_rule_no_fire("AUT-003", context("https://shop.example.com/reset?token=" + "a" * 40))


def test_aut004_logout_keeps_cookie():
    logout = "https://shop.example.com/logout"
    assert_rule_fires("AUT-004", context(logout))
    assert_rule_no_fire("AUT-004", context(logout, cookies=["sid=; Max-Age=0; Path=/"]))


def test_aut005_user_enumeration():
    login = "https://shop.example.com/login"
    assert_rule_fires("AUT-005", context(login, body="<p>User not found</p>"))
    assert_rule_no_fire("AUT-005", context(login, body="<p>Invalid credentials</p>"))


def test_aut006_default_credential_surface():
    assert_rule_fires("AUT-006", context(body="<title>Jenkins</title>"))
    assert_rule_no_fire("AUT-006", context(body="<title>Shop</title>"))


def test_aut007_redirect_parameter():
    assert_rule_fires("AUT-007", context("https://shop.example.com/login?next=/home"))
    assert_rule_no_fire("AUT-007", context("https://shop.example.com/login?page=2"))


# Cookies


def test_cki004_session_token_in_url():
    assert_rule_fires("CKI-004", context("https://shop.example.com/a?sessionid=abc"))
    assert_rule_no_fire("CKI-004", context("https://shop.example.com/a?author=abc"))


def test_cki005_broad_cookie_scope():
    assert_rule_fires("CKI-005", context(cookies=["sid=x; Domain=.example.com"]))
    assert_rule_no_fire("CKI-005", context(cookies=["sid=x; Path=/; Secure"]))


def test_cki006_short_session_cookie():
    assert_rule_fires("CKI-006", context(cookies=["sessionid=abc"]))
    assert_rule_no_fire("CKI-006", context(cookies=["sessionid=" + "a1" * 16]))


# CORS


def test_cor001_wildcard_origin():
    assert_rule_fires("COR-001", context(cors_acao="*"))
    assert_rule_no_fire("COR-001", context(cors_acao="https://shop.example.com"))


def test_cor004_unsafe_methods_cross_origin():
    assert_rule_fires(
        "COR-004", context(cors_acao="https://a.example", cors_methods="GET, PUT, DELETE")
    )
    assert_rule_no_fire("COR-004", context(cors_acao="https://a.example", cors_methods="GET, POST"))


def test_cor005_preflight_without_max_age():
    assert_rule_fires("COR-005", context(cors_preflight_acao="https://a.example"))
    assert_rule_no_fire(
        "COR-005", context(cors_preflight_acao="https://a.example", cors_max_age="600")
    )


# Headers


def test_hdr009_coop():
    assert_rule_fires("HDR-009", context())
    assert_rule_no_fire("HDR-009", context(headers={"Cross-Origin-Opener-Policy": "same-origin"}))


def test_hdr010_corp():
    assert_rule_fires("HDR-010", context())
    assert_rule_no_fire("HDR-010", context(headers={"Cross-Origin-Resource-Policy": "same-origin"}))


def test_hdr011_cache_on_sensitive_endpoint():
    assert_rule_fires(
        "HDR-011", context(context_class=ContextClass.HIGH, headers={"Cache-Control": "public"})
    )
    assert_rule_no_fire(
        "HDR-011", context(context_class=ContextClass.HIGH, headers={"Cache-Control": "no-store"})
    )
    assert_rule_no_fire("HDR-011", context(context_class=ContextClass.LOW))


def test_hdr012_expect_ct():
    hsts = {"Strict-Transport-Security": "max-age=31536000"}
    assert_rule_fires("HDR-012", context(headers=hsts))
    assert_rule_no_fire("HDR-012", context(headers={**hsts, "Expect-CT": "max-age=86400"}))


# Information disclosure


def test_inf001_internal_ip():
    assert_rule_fires("INF-001", context(body_class=BodyClassification(internal_ip=True)))
    assert_rule_no_fire("INF-001", context(body_class=BodyClassification()))


def test_inf006_api_docs():
    assert_rule_fires("INF-006", context(body='{"openapi": "3.0.0", "paths": {}}'))
    assert_rule_no_fire("INF-006", context(body="<html>Shop</html>"))


# TLS


def test_tls001_legacy_protocols():
    assert_rule_fires("TLS-001", context(tls=_tls(protocols_offered=["TLSv1", "TLSv1.2"])))
    assert_rule_no_fire("TLS-001", context(tls=_tls(protocols_offered=["TLSv1.2", "TLSv1.3"])))


def test_tls002_weak_cipher():
    assert_rule_fires("TLS-002", context(tls=_tls(negotiated_cipher="TLS_RSA_WITH_RC4_128_SHA")))
    assert_rule_no_fire("TLS-002", context(tls=_tls(negotiated_cipher="TLS_AES_128_GCM_SHA256")))


def test_tls003_certificate_expiry():
    now = datetime.now(UTC)
    assert_rule_fires("TLS-003", context(tls=_tls(cert_not_after=now - timedelta(days=1))))
    assert_rule_fires("TLS-003", context(tls=_tls(cert_not_after=now + timedelta(days=5))))
    assert_rule_no_fire("TLS-003", context(tls=_tls(cert_not_after=now + timedelta(days=90))))


def test_tls004_self_signed():
    assert_rule_fires("TLS-004", context(tls=_tls(is_self_signed=True)))
    assert_rule_no_fire("TLS-004", context(tls=_tls(is_self_signed=False)))


def test_tls006_mixed_content():
    assert_rule_fires("TLS-006", context(body='<img src="http://cdn.example/a.png">'))
    assert_rule_no_fire("TLS-006", context(body='<img src="https://cdn.example/a.png">'))


def test_tls007_hsts_without_preload():
    assert_rule_fires("TLS-007", context(headers={"Strict-Transport-Security": "max-age=31536000"}))
    assert_rule_no_fire(
        "TLS-007", context(headers={"Strict-Transport-Security": "max-age=31536000; preload"})
    )


def test_tls008_hostname_mismatch():
    assert_rule_fires("TLS-008", context(tls=_tls(hostname_matches=False)))
    assert_rule_no_fire("TLS-008", context(tls=_tls(hostname_matches=True)))


def test_tls_rules_never_fire_without_a_probe():
    for rule_id in ("TLS-001", "TLS-002", "TLS-003", "TLS-004", "TLS-008"):
        assert_rule_no_fire(rule_id, context(tls=None))


def test_a_check_with_a_spec_reports_the_spec_vector():
    """One check id, one base vector: a legacy rule whose id has a checks.yaml
    spec (the five blocked ones) reports the spec's vector, not the catalog's."""
    from app.core.checks.base import make
    from app.core.checks.catalog import CATALOG
    from app.core.checks.registry import load_specs
    from app.core.cvss31 import base_score

    specs = load_specs()
    for rule_id in sorted(set(CATALOG) & set(specs)):
        finding = make(rule_id, "evidence")
        assert finding.cvss_vector == specs[rule_id].base_cvss_vector, rule_id
        assert finding.base_score == base_score(specs[rule_id].base_cvss_vector), rule_id
    assert make("HDR-009").cvss_vector == CATALOG["HDR-009"].cvss_vector  # no spec
