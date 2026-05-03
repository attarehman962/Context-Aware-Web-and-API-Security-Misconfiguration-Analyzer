"""Response body sensitivity detection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


PATTERNS = {
    "pii.email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}") ,
    "pii.phone": re.compile(r"\+?\d[\d\s().-]{7,}\d"),
    "secret.jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    "secret.api_key": re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[A-Za-z0-9._-]{8,}"),
    "financial.amount": re.compile(r"(?i)(amount|total|balance|price|currency)"),
    "infra.hostname": re.compile(r"(?i)(internal|private|staging|prod|cluster|k8s|docker|vm)"),
}


@dataclass
class BodySignals:
    labels: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def as_bonus(self) -> float:
        return min(2.5, 0.5 + 0.4 * len(self.labels))


def classify_body(content: str) -> BodySignals:
    labels = [name for name, pattern in PATTERNS.items() if pattern.search(content)]
    confidence = min(0.99, 0.4 + 0.12 * len(labels)) if labels else 0.0
    return BodySignals(labels=labels, confidence=round(confidence, 2))
