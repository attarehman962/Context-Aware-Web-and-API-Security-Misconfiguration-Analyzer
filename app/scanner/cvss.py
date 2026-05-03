"""CVSS adjustment logic for CAWASMA."""

from __future__ import annotations

from dataclasses import dataclass


SENSITIVITY_MULTIPLIERS = {
    "LOW": 0.9,
    "MEDIUM": 1.0,
    "HIGH": 1.2,
    "CRITICAL": 1.4,
}

SEVERITY_LABELS = (
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
)


@dataclass
class CVSSResult:
    base_score: float
    adjusted_score: float
    severity: str
    explanation: str


def severity_from_score(score: float) -> str:
    for threshold, label in SEVERITY_LABELS:
        if score >= threshold:
            return label
    return "INFO"


def adjust_score(base_score: float, sensitivity: str, body_bonus: float = 0.0) -> CVSSResult:
    multiplier = SENSITIVITY_MULTIPLIERS.get(sensitivity, 1.0)
    adjusted = round(min(10.0, (base_score * multiplier) + body_bonus), 1)
    severity = severity_from_score(adjusted)
    explanation = f"base={base_score}, sensitivity_multiplier={multiplier}, body_bonus={body_bonus}"
    return CVSSResult(base_score=base_score, adjusted_score=adjusted, severity=severity, explanation=explanation)
