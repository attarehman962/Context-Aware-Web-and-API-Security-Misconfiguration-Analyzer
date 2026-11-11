"""CVSS v3.1 base vectors: strict parsing and base-score calculation.

Implements the base equations from the FIRST CVSS v3.1 specification (section
7.1, including the ``Roundup`` of Appendix A). Used to validate the
``base_cvss_vector`` of check specs and to derive their base score, so a score
can never disagree with its vector.

Environmental metrics (CR/IR/AR and modified base metrics) are not handled yet;
see "Current state vs goal" in CLAUDE.md.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

PREFIX = "CVSS:3.1/"

# Metric -> allowed values, in the specification's canonical order.
BASE_METRICS: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("H", "L", "N"),
    "I": ("H", "L", "N"),
    "A": ("H", "L", "N"),
}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


class CvssVectorError(ValueError):
    """Raised for a malformed or non-base CVSS v3.1 vector."""


@dataclass(frozen=True)
class BaseVector:
    metrics: dict[str, str]

    @property
    def scope_changed(self) -> bool:
        """True if the CVSS scope metric is Changed (S:C)."""
        return self.metrics["S"] == "C"

    def __str__(self) -> str:
        """Render the metrics back into a CVSS v3.1 vector string."""
        return PREFIX + "/".join(f"{m}:{self.metrics[m]}" for m in BASE_METRICS)


def parse_base_vector(vector: str) -> BaseVector:
    """Parse ``CVSS:3.1/AV:..`` with exactly the 8 base metrics, in canonical order.

    Rejects other CVSS versions, unknown/duplicate/missing metrics, invalid
    values and temporal/environmental metrics.
    """
    if not isinstance(vector, str) or not vector.startswith(PREFIX):
        raise CvssVectorError(f"must start with {PREFIX!r}")
    parts = vector[len(PREFIX) :].split("/")
    metrics: dict[str, str] = {}
    for part in parts:
        name, sep, value = part.partition(":")
        if not sep or not name or not value:
            raise CvssVectorError(f"malformed metric {part!r}")
        if name not in BASE_METRICS:
            raise CvssVectorError(f"{name!r} is not a CVSS v3.1 base metric")
        if name in metrics:
            raise CvssVectorError(f"metric {name!r} appears twice")
        if value not in BASE_METRICS[name]:
            allowed = "/".join(BASE_METRICS[name])
            raise CvssVectorError(f"invalid value {value!r} for {name} (allowed: {allowed})")
        metrics[name] = value
    missing = [m for m in BASE_METRICS if m not in metrics]
    if missing:
        raise CvssVectorError(f"missing base metric(s): {', '.join(missing)}")
    if list(metrics) != list(BASE_METRICS):
        raise CvssVectorError("metrics must be in order " + "/".join(BASE_METRICS))
    return BaseVector(metrics)


def roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest 1-decimal number >= value, float-safe."""
    as_int = round(value * 100_000)
    if as_int % 10_000 == 0:
        return as_int / 100_000.0
    return (math.floor(as_int / 10_000) + 1) / 10.0


def base_score(vector: str | BaseVector) -> float:
    """CVSS v3.1 base score (0.0-10.0) for a base vector."""
    v = vector if isinstance(vector, BaseVector) else parse_base_vector(vector)
    m = v.metrics
    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if v.scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr = (_PR_CHANGED if v.scope_changed else _PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if v.scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10.0))
    return roundup(min(impact + exploitability, 10.0))
