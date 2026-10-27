"""app/ml/body_classifier.py (Asim Prompt 7).

Every kind has fixtures in tests/fixtures/bodies/ that must fire and near-misses
that must not: ``<kind>.<fire|miss>.<case>.<ext>``; the extension gives the
content type. Realistic secrets are written as ``{{NAME}}`` placeholders and
expanded here, so the repository never holds a string that looks like a live
AWS key or private key (and GitHub push protection doesn't block it).
"""
from __future__ import annotations

import base64
import importlib.util
import json
import time
from pathlib import Path

import pytest

from app.core.contracts import BodySignal, ResponseInfo, check_conformance
from app.ml import body_classifier as bc
from app.ml import sensitivity

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "bodies"
CONTENT_TYPES = {".json": "application/json", ".html": "text/html; charset=utf-8",
                 ".txt": "text/plain", ".js": "application/javascript",
                 ".env": "application/octet-stream"}     # how crAPI serves its /.env


def _b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


TOKENS = {   # assembled at run time; see the module docstring
    "AWS_KEY": "AKIA" + "Q3EGRZ7X2MPLWXYZ",
    "AWS_SECRET": "wJ8rPqZ2mN7vB4xK" + "9sL1dF6hG3jT5yU0cE2aR8wQ",
    "PEM_BEGIN": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "JWT": ".".join([_b64url({"alg": "HS256", "typ": "JWT"}),
                     _b64url({"sub": "42", "role": "customer"}),
                     "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"]),
    "STRIPE": "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "GITHUB": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
}
# Secret values in the fire fixtures: none may appear in any evidence.
# (The PEM header line is a marker, not a secret: the key material after it is.)
SECRETS = [*(v for k, v in TOKENS.items() if k != "PEM_BEGIN"), "Hunter2!x", "S3cretPw9",
           "s3cr3tPass77", "S3cr3t!", "Tr0ub4dor9", "Xk92pwQ", "Pa55w0rd!",
           "q8Zr2LmX9vT4kP1sW7nB", "4567891", "Rk7tq2Lw9"]
HAS_SPACY = importlib.util.find_spec("spacy") is not None


def _load(path: Path) -> ResponseInfo:
    body = path.read_text()
    for name, value in TOKENS.items():
        body = body.replace("{{" + name + "}}", value)
    return ResponseInfo(url=f"https://shop.example.com/{path.stem}", status_code=200,
                        content_type=CONTENT_TYPES[path.suffix], body=body)


def _cases(outcome: str) -> list:
    out = []
    for path in sorted(FIXTURES.glob(f"*.{outcome}.*")):
        kind = path.name.split(".")[0]
        marks = ([pytest.mark.skipif(not HAS_SPACY, reason="person names need spaCy")]
                 if "person-name" in path.name else [])
        out.append(pytest.param(kind, path, id=path.stem, marks=marks))
    return out


@pytest.mark.parametrize("kind, path", _cases("fire"))
def test_fires(kind, path):
    kinds = {d.kind for d in bc.detect(_load(path))}
    assert kind in kinds, f"{path.name}: got {kinds}"


@pytest.mark.parametrize("kind, path", _cases("miss"))
def test_near_miss_does_not_fire(kind, path):
    hits = [d for d in bc.detect(_load(path)) if d.kind == kind]
    assert not hits, f"{path.name}: {hits}"


def test_every_kind_has_fire_and_miss_fixtures():
    for kind in bc.KIND_SIGNAL:
        assert list(FIXTURES.glob(f"{kind}.fire.*")), kind
        assert list(FIXTURES.glob(f"{kind}.miss.*")), kind


def test_evidence_never_contains_a_full_secret():
    for path in FIXTURES.glob("*.fire.*"):
        for d in bc.detect(_load(path)):
            for secret in SECRETS:
                assert secret not in d.evidence, (path.name, d)


def test_redaction_format():
    assert bc.mask(TOKENS["AWS_KEY"]) == "AKIA****WXYZ"
    assert bc.mask("short") == "****"
    [card] = [d for d in bc.detect(_load(FIXTURES / "financial.fire.card-visa.json"))]
    assert card.evidence.startswith("****") and len(card.evidence) == 8


# ------------------------------------------------------ signals + contract

def test_kinds_map_onto_the_four_contract_signals():
    assert bc.analyze(_load(FIXTURES / "secret_key.fire.jwt.json")) == {BodySignal.CREDENTIALS}
    assert bc.analyze(_load(FIXTURES / "credential.fire.json-password.json")) == {
        BodySignal.CREDENTIALS}
    assert bc.analyze(_load(FIXTURES / "stack_trace.fire.python.txt")) == set()
    assert bc.analyze(_load(FIXTURES / "internal_ip.fire.loopback.txt")) == {
        BodySignal.INTERNAL_IP}


def test_conforms_to_the_ml_contract():
    assert check_conformance(sensitivity.classify, bc.analyze) == []


def test_never_raises(monkeypatch):
    def boom(text):
        raise RuntimeError("bug")
        yield

    monkeypatch.setattr(bc, "_DETECTORS", ((boom, ()),))
    assert bc.analyze(_load(FIXTURES / "pii.fire.email.json")) == set()


# ------------------------------------------------------ scope and limits

def test_only_text_like_content_is_scanned():
    body = '{"password": "Hunter2!x"}'
    for ctype, fires in [("application/json", True), ("text/html", True),
                         ("application/problem+json", True), ("image/png", False),
                         ("application/octet-stream", True),   # sniffed: type unknown
                         ("font/woff2", False)]:
        r = ResponseInfo("https://x.test/a", 200, ctype, body=body)
        assert bool(bc.detect(r)) is fires, ctype


def test_untyped_bodies_are_sniffed():
    assert bc.detect(ResponseInfo("https://x.test/a", 200, None, body='{"password": "Hunter2!x"}'))
    for ctype in (None, "application/octet-stream"):
        assert not bc.detect(ResponseInfo("https://x.test/a", 200, ctype,
                                          body='\x00\x01{"password": "Hunter2!x"}'))


def test_body_is_capped():
    tail = "x" * bc.MAX_SCAN_CHARS + ' {"password": "Hunter2!x"}'
    assert not bc.detect(ResponseInfo("https://x.test/a", 200, "text/plain", body=tail))


def test_fast_enough_for_200_calls_per_scan():
    body = (FIXTURES / "credential.fire.json-password.json").read_text() * 2000   # ~150 KB
    r = ResponseInfo("https://x.test/a", 200, "application/json", body=body)
    bc.detect(r)                                   # warm-up (spaCy load, if any)
    start = time.perf_counter()
    for _ in range(20):
        bc.analyze(r)
    assert (time.perf_counter() - start) / 20 < 0.05
