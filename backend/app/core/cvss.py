"""CVSS scoring: official base score, and the context-aware environmental score.

Two ways to score, kept strictly apart from the official base score:

* :func:`environmental_score` / :func:`score_finding` (**the target**):
  the check's CVSS v3.1 base vector from checks.yaml is re-scored
  through the CVSS v3.1 *environmental* metrics. The endpoint's sensitivity
  class and the response's body signals set the Security Requirements
  (CR/IR/AR) via config/cvss_mapping.yaml; nothing else changes (no modified
  base metrics), so every result is a standard, re-computable CVSS vector.
  Scores come from the ``cvss`` library; the formula is not re-implemented.
* :func:`compute_score` (**interim**, docs/06-scoring-model.md):
  ``min(10, base x context multiplier + response bonus)``. The pipeline still
  uses it for the legacy catalog rules until they move to checks.yaml.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from app.core.contracts import BodySignal
from app.db.models.enums import ContextClass, Severity

if TYPE_CHECKING:  # imported lazily below: specs.py imports this module
    from app.core.checks.registry import RawFinding
    from app.core.specs import CvssMapping

# Endpoint context multipliers.
CONTEXT_MULTIPLIERS: dict[ContextClass, float] = {
    ContextClass.CRITICAL: 2.0,
    ContextClass.HIGH: 1.5,
    ContextClass.MEDIUM: 1.0,
    ContextClass.LOW: 0.6,
}

# Response-body bonuses.
RESPONSE_BONUS = {
    "credentials": 3.5,
    "pii": 2.0,
    "financial": 1.5,
    "internal_ip": 2.0,
}

MAX_SCORE = 10.0


def severity_for(score: float) -> Severity:
    """Map a 0-10 score to a severity bucket."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return Severity.INFO


@dataclass
class ScoreResult:
    cvss_base_score: float
    context_multiplier: float
    response_bonus: float
    cawasma_final_score: float
    severity: Severity


def compute_score(
    base_cvss: float,
    context_class: ContextClass | None,
    response_bonus: float = 0.0,
    *,
    force_critical: bool = False,
) -> ScoreResult:
    """Apply the CAWASMA formula and derive severity.

    ``force_critical`` reflects the rule that credential exposure forces the
    final severity to CRITICAL, regardless of the numeric score.
    """
    multiplier = CONTEXT_MULTIPLIERS.get(context_class or ContextClass.MEDIUM, 1.0)
    raw = (base_cvss * multiplier) + response_bonus
    final = round(min(MAX_SCORE, raw), 1)
    severity = severity_for(final)
    if force_critical:
        severity = Severity.CRITICAL
        final = max(final, 9.0)
    return ScoreResult(
        cvss_base_score=base_cvss,
        context_multiplier=multiplier,
        response_bonus=response_bonus,
        cawasma_final_score=final,
        severity=severity,
    )


# CVSS v3.1 environmental scoring

_REQUIREMENT_ORDER = {"L": 1, "M": 2, "H": 3}  # X (Not Defined) contributes nothing
_V31_BUCKETS = (
    (9.0, Severity.CRITICAL, "Critical"),
    (7.0, Severity.HIGH, "High"),
    (4.0, Severity.MEDIUM, "Medium"),
    (0.1, Severity.LOW, "Low"),
)


@dataclass(frozen=True)
class ContextScore:
    """A finding's context-aware score.

    ``vector`` is the base vector plus ``/CR:../IR:../AR:..`` (always all three,
    ``X`` included, so the requirements are visible). ``base_score`` is the
    official CVSS v3.1 base score; ``final_score`` the environmental score.
    ``score_reasons`` is a short, stable, machine-readable explanation:
    ``sensitivity:<CLASS>``, ``signal:<SIGNAL>``, ``<REQ>:<L|M|H><-<source>[+<source>]``
    for each requirement set, ``no-context-change`` when none is,
    ``base:<score>`` and ``environmental:<score>``.
    """

    vector: str
    base_score: float
    final_score: float
    severity_bucket: Severity
    cvss_severity: str  # "None", "Low", "Medium", "High", "Critical"
    requirements: dict[str, str]
    score_reasons: list[str]


def severity_bucket(score: float) -> tuple[Severity, str]:
    """CVSS v3.1 qualitative rating: None 0.0, Low 0.1-3.9, Medium 4.0-6.9,
    High 7.0-8.9, Critical 9.0-10.0. "None" is stored as ``Severity.INFO``."""
    for floor, bucket, name in _V31_BUCKETS:
        if score >= floor:
            return bucket, name
    return Severity.INFO, "None"


def _mapping_path() -> str:
    """Path to the CVSS environmental mapping YAML file."""
    from pathlib import Path

    from app.config import settings

    return str(Path(settings.CONFIG_DIR) / "cvss_mapping.yaml")


def load_mapping(path: str | None = None) -> CvssMapping:
    """Load config/cvss_mapping.yaml, validated (cached per path)."""
    return _load_mapping_cached(path or _mapping_path())


@lru_cache
def _load_mapping_cached(path: str) -> CvssMapping:
    """Load and cache the parsed CVSS mapping for a path."""
    from app.core.specs import load_cvss_mapping

    return load_cvss_mapping(path)


def security_requirements(
    sensitivity: ContextClass,
    signals: Iterable[BodySignal | str],
    mapping: CvssMapping | None = None,
) -> tuple[dict[str, str], list[str]]:
    """CR/IR/AR for a context, and where each one came from.

    The class row is the starting point; each body signal can only raise a
    requirement (``combine: max``, ordered L < M < H, ``X`` adds nothing).
    """
    mapping = mapping or load_mapping()
    rows = [(f"sensitivity:{sensitivity.value}", mapping.sensitivity_classes[sensitivity])]
    for signal in sorted({BodySignal(s) for s in signals}, key=lambda s: s.value):
        rows.append((f"signal:{signal.value}", mapping.body_signals[signal]))

    requirements: dict[str, str] = {}
    reasons = [source for source, _ in rows]
    for metric in ("CR", "IR", "AR"):
        values = [
            (getattr(row, metric), source) for source, row in rows if getattr(row, metric) != "X"
        ]
        if not values:
            requirements[metric] = "X"
            continue
        top = max(_REQUIREMENT_ORDER[v] for v, _ in values)
        value = next(v for v, _ in values if _REQUIREMENT_ORDER[v] == top)
        requirements[metric] = value
        sources = [src for v, src in values if v == value]
        reasons.append(f"{metric}:{value}<-{'+'.join(sources)}")
    return requirements, reasons


def environmental_score(
    base_vector: str,
    sensitivity: ContextClass,
    signals: Iterable[BodySignal | str],
    mapping: CvssMapping | None = None,
) -> ContextScore:
    """Re-score a CVSS v3.1 *base* vector for an endpoint's context."""
    from cvss import CVSS3

    from app.core.cvss31 import CvssVectorError, parse_base_vector

    try:
        parse_base_vector(base_vector)
    except CvssVectorError as exc:
        raise ValueError(f"expected a CVSS v3.1 base vector: {exc}") from exc

    requirements, reasons = security_requirements(sensitivity, signals, mapping)
    vector = base_vector + "".join(f"/{m}:{requirements[m]}" for m in ("CR", "IR", "AR"))
    scored = CVSS3(vector)
    base, final = float(scored.base_score), float(scored.environmental_score)
    if all(v == "X" for v in requirements.values()):
        reasons.append("no-context-change")
    reasons += [f"base:{base}", f"environmental:{final}"]
    bucket, name = severity_bucket(final)
    return ContextScore(
        vector=vector,
        base_score=base,
        final_score=final,
        severity_bucket=bucket,
        cvss_severity=name,
        requirements=requirements,
        score_reasons=reasons,
    )


def score_finding(
    finding: RawFinding,
    sensitivity: ContextClass,
    signals: Iterable[BodySignal | str],
    mapping: CvssMapping | None = None,
) -> ContextScore:
    """Score a registry ``RawFinding`` with its check's base vector from checks.yaml."""
    from app.core.checks.registry import spec_for

    return environmental_score(
        spec_for(finding.check_id).base_cvss_vector, sensitivity, signals, mapping
    )
