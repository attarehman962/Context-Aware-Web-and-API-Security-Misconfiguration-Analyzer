"""CKI-001..003 (spec/cookies.py), COR-002/COR-003 (spec/cors.py)."""
from __future__ import annotations

import pytest

from tests.checks.helpers import assert_fires, assert_no_fire, response

SAFE = "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
PROBE = {"Origin": "https://cawasma-probe-1f2e.example"}


@pytest.mark.parametrize("check_id, cookie", [
    ("CKI-001", "PHPSESSID=abc; path=/; Secure; SameSite=Lax"),
    ("CKI-002", "session=abc; HttpOnly; SameSite=Strict"),
    ("CKI-003", "auth_token=abc; Secure; HttpOnly"),
])
def test_session_cookie_missing_a_flag_fires(check_id, cookie):
    [f] = assert_fires(check_id, response(cookies=[cookie]))
    assert "abc" not in str(f.evidence)            # metadata only, never the value


@pytest.mark.parametrize("check_id", ["CKI-001", "CKI-002", "CKI-003"])
def test_fully_flagged_session_cookie_no_fire(check_id):
    assert_no_fire(check_id, response(cookies=[SAFE]))


@pytest.mark.parametrize("check_id", ["CKI-001", "CKI-002", "CKI-003"])
def test_non_session_cookie_no_fire(check_id):
    assert_no_fire(check_id, response(cookies=["theme=dark; Path=/"]))


def test_each_cookie_is_judged_separately():
    # The bad cookie comes first: a folded header dict would only show the last.
    found = assert_fires("CKI-001", response(cookies=["PHPSESSID=x; Secure; SameSite=Lax", SAFE]))
    assert [f.evidence["cookie"]["name"] for f in found] == ["PHPSESSID"]
    assert_no_fire("CKI-001", response(cookies=[SAFE, "lang=en"]))


def _preflight(headers, sent=PROBE):
    return response(method="OPTIONS", headers=headers, request_headers=sent)


def test_cor003_fires_on_wildcard_with_credentials():
    assert_fires("COR-003", _preflight({"Access-Control-Allow-Origin": "*",
                                        "Access-Control-Allow-Credentials": "true"}))


@pytest.mark.parametrize("headers", [{"Access-Control-Allow-Origin": "*"},
                                     {"Access-Control-Allow-Origin": "https://app.example",
                                      "Access-Control-Allow-Credentials": "true"}])
def test_cor003_no_fire_without_both(headers):
    assert_no_fire("COR-003", _preflight(headers))


def test_cor003_only_judges_the_preflight():
    get = response(headers={"Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Credentials": "true"})
    assert_no_fire("COR-003", get)


def test_cor002_fires_when_the_probe_origin_is_reflected():
    [f] = assert_fires("COR-002", _preflight(
        {"Access-Control-Allow-Origin": PROBE["Origin"],
         "Access-Control-Allow-Credentials": "true"}))
    assert f.evidence["origin_sent"] == PROBE["Origin"]


@pytest.mark.parametrize("headers, sent", [
    ({"Access-Control-Allow-Origin": "*"}, PROBE),                     # wildcard, not reflection
    ({"Access-Control-Allow-Origin": "https://app.example"}, PROBE),   # fixed allow-list
    ({}, PROBE),                                                       # no CORS
    ({"Access-Control-Allow-Origin": PROBE["Origin"]}, {}),            # we sent no Origin
])
def test_cor002_no_fire_unless_the_exact_origin_comes_back(headers, sent):
    assert_no_fire("COR-002", _preflight(headers, sent))


def test_cki002_secure_explicitly():
    assert_fires("CKI-002", response(cookies=["sid=1; HttpOnly; SameSite=Lax"]))
    assert_no_fire("CKI-002", response(cookies=["sid=1; Secure; HttpOnly; SameSite=Lax"]))


def test_cki003_samesite_explicitly():
    assert_fires("CKI-003", response(cookies=["jwt=1; Secure; HttpOnly"]))
    assert_no_fire("CKI-003", response(cookies=["jwt=1; Secure; HttpOnly; SameSite=Strict"]))
