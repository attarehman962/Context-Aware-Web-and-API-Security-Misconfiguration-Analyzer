"""Engine <-> ML contract, version 1 (docs/cvss-mapping-contract.md).

Asim's code provides two functions with these exact signatures:

* ``app.ml.sensitivity.classify(endpoint: EndpointInfo) -> SensitivityClass``
* ``app.ml.body_classifier.analyze(response: ResponseInfo) -> set[BodySignal]``

Until those modules exist the engine uses :func:`builtin_classify` and
:func:`builtin_analyze`, which wrap the existing keyword/regex classifiers and
satisfy the same contract. :func:`check_conformance` is the executable check
both implementations must pass.
"""

from __future__ import annotations

import enum
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from app.db.models.enums import ContextClass

ML_CONTRACT_VERSION = "1.1.0"  # 1.1: chains.yaml groups/scope/context/vectors

#: Endpoint sensitivity: CRITICAL, HIGH, MEDIUM, LOW (same values as the DB enum).
SensitivityClass = ContextClass


class BodySignal(str, enum.Enum):
    """Sensitive data detected in a response body."""

    CREDENTIALS = "CREDENTIALS"  # passwords, API keys, tokens, private keys
    PII = "PII"  # emails, phone numbers, national IDs
    FINANCIAL = "FINANCIAL"  # card numbers (Luhn-valid), IBANs
    INTERNAL_IP = "INTERNAL_IP"  # RFC 1918 / loopback / link-local addresses


@dataclass(frozen=True)
class EndpointInfo:
    """What the engine knows about an endpoint when classifying it."""

    url: str  # absolute URL, e.g. https://shop.example.com/api/v1/users/42
    path: str  # path only, e.g. /api/v1/users/42
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None


@dataclass(frozen=True)
class ResponseInfo:
    """A response as passed to the body analyzer. ``body`` is already truncated
    to ``MAX_RESPONSE_SIZE`` and decoded as text (empty for binary bodies)."""

    url: str
    status_code: int
    content_type: str | None
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str = ""


ClassifyFn = Callable[[EndpointInfo], SensitivityClass]
AnalyzeFn = Callable[[ResponseInfo], set[BodySignal]]


# ------------------------------------------------- built-in implementations


def builtin_classify(endpoint: EndpointInfo) -> SensitivityClass:
    """Keyword (+ optional embedding) classifier from ``core/sensitivity.py``."""
    from app.core.sensitivity import get_classifier

    return get_classifier().classify(endpoint.path).context_class


def builtin_analyze(response: ResponseInfo) -> set[BodySignal]:
    """Regex/Luhn body classifier from ``core/body_classifier.py``."""
    from app.core.body_classifier import classify_body

    result = classify_body(response.body, response.content_type)
    flags = {
        BodySignal.CREDENTIALS: result.credentials,
        BodySignal.PII: result.pii,
        BodySignal.FINANCIAL: result.financial,
        BodySignal.INTERNAL_IP: result.internal_ip,
    }
    return {signal for signal, present in flags.items() if present}


# ---------------------------------------------------------------- conformance

_PROBE_ENDPOINTS = [
    EndpointInfo("https://shop.example.com/", "/"),
    EndpointInfo("https://shop.example.com/api/v1/login", "/api/v1/login", "POST"),
    EndpointInfo(
        "https://shop.example.com/static/a%20b.js",
        "/static/a%20b.js",
        content_type="application/javascript",
    ),
    EndpointInfo("https://shop.example.com/" + "x" * 2000, "/" + "x" * 2000),
]
_PROBE_RESPONSES = [
    ResponseInfo("https://shop.example.com/", 200, "text/html", body=""),
    ResponseInfo(
        "https://shop.example.com/.env",
        200,
        "text/plain",
        body="DB_PASSWORD=hunter2\nAWS_SECRET_ACCESS_KEY=abc",
    ),
    ResponseInfo("https://shop.example.com/img", 200, "image/png", body=""),
    ResponseInfo("https://shop.example.com/err", 500, None, body="\x00�" * 100),
]


def check_conformance(classify: ClassifyFn, analyze: AnalyzeFn) -> list[str]:
    """Return contract violations for an implementation (empty list = conforms).

    Checks the return types, that edge-case inputs don't raise, and that results
    are deterministic. It does not judge accuracy -- that is Asim's evaluation.
    """
    problems: list[str] = []
    for ep in _PROBE_ENDPOINTS:
        try:
            first, second = classify(ep), classify(ep)
        except Exception as exc:  # noqa: BLE001 - reporting, not handling
            problems.append(f"classify({ep.path[:40]!r}) raised {exc!r}")
            continue
        if not isinstance(first, SensitivityClass):
            problems.append(f"classify({ep.path[:40]!r}) returned {first!r}, not SensitivityClass")
        elif first != second:
            problems.append(f"classify({ep.path[:40]!r}) is not deterministic")
    for resp in _PROBE_RESPONSES:
        try:
            signals = analyze(resp)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"analyze({resp.url!r}) raised {exc!r}")
            continue
        if not isinstance(signals, set) or not all(isinstance(s, BodySignal) for s in signals):
            problems.append(f"analyze({resp.url!r}) returned {signals!r}, not set[BodySignal]")
    return problems
