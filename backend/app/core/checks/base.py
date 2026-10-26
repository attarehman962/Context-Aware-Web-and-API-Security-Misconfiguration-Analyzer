"""Check framework: the context passed to every rule and the raw finding type.

Rules are pure functions ``detect(ctx) -> RawFinding | None``. They read only
from the :class:`CheckContext` and never touch the database, so each is trivial
to unit-test. The registry is populated by importing the category modules.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from app.core.body_classifier import BodyClassification
from app.core.catalog_ref import CATALOG  # re-export for rule modules
from app.core.cvss import severity_for
from app.core.cvss31 import base_score as vector_base_score
from app.core.engine import HttpResult
from app.core.tls import TlsProbe
from app.db.models.enums import ContextClass, FindingCategory, Severity


@dataclass
class CheckContext:
    """Everything a rule may need about one endpoint (+ scan-level signals)."""

    url: str
    path: str
    result: HttpResult
    context_class: ContextClass | None = None
    body_class: BodyClassification | None = None

    # Optional probe-derived signals (populated by the pipeline in Phase 13).
    allowed_methods: set[str] = field(default_factory=set)
    cors_acao: str | None = None            # Access-Control-Allow-Origin (probe)
    cors_acac: str | None = None            # Access-Control-Allow-Credentials
    cors_methods: str | None = None         # Access-Control-Allow-Methods
    cors_preflight_acao: str | None = None  # ACAO on a real preflight (OPTIONS + Origin)
    cors_max_age: str | None = None         # Access-Control-Max-Age on that preflight
    probe_origin: str = "https://cawasma-probe.example"
    tls: TlsProbe | None = None
    http_scheme_redirects_https: bool | None = None
    graphql_introspection: bool = False
    injection_error_reflected: bool = False

    def header(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.result.headers.items():
            if k.lower() == low:
                return v
        return None

    def has_header(self, name: str) -> bool:
        return self.header(name) is not None


@dataclass
class RawFinding:
    rule_id: str
    title: str
    category: FindingCategory
    base_severity: Severity
    cvss_vector: str
    base_score: float
    evidence: str | None = None
    impact: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    limitation: str | None = None


DetectFn = Callable[[CheckContext], "RawFinding | None"]
REGISTRY: list[DetectFn] = []


def query_names(url: str) -> set[str]:
    """Lowercased query parameter names of ``url`` (``?a=1&B=2`` -> {"a", "b"})."""
    from urllib.parse import parse_qsl, urlparse

    return {k.lower() for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}


def rule(fn: DetectFn) -> DetectFn:
    """Register a detection function."""
    REGISTRY.append(fn)
    return fn


def make(rule_id: str, evidence: str | None = None) -> RawFinding:
    """Build a RawFinding from catalog metadata + runtime evidence.

    The base score is computed from the catalog's CVSS vector, never taken from
    its hand-written ``base_score``: 31 entries disagree with their own vector
    (``make validate-config`` lists them), and the API promises that
    ``base_score`` is the official score of ``cvss_vector``.
    """
    meta = CATALOG[rule_id]
    score = vector_base_score(meta.cvss_vector)
    return RawFinding(
        rule_id=meta.rule_id,
        title=meta.name,
        category=meta.category,
        base_severity=severity_for(score),
        cvss_vector=meta.cvss_vector,
        base_score=score,
        evidence=evidence,
        impact=meta.impact,
        recommendation=meta.recommendation,
        references=list(meta.references),
        limitation=meta.limitation,
    )
