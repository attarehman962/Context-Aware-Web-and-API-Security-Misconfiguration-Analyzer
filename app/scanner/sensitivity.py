"""Endpoint sensitivity classification."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
ABBREVIATIONS = {
    "iam": "identity access management",
    "svc": "service",
    "ms": "microservice",
    "auth": "authentication",
    "billing": "billing",
    "admin": "administrator",
    "priv": "privileged",
    "webhook": "webhook",
}

ANCHORS = {
    "CRITICAL": "payments secrets credentials admin privileged billing wallet webhook token account takeover",
    "HIGH": "identity authentication authorization user profile session login order finance api",
    "MEDIUM": "dashboard settings search report export review content customer",
    "LOW": "static assets help docs marketing public health robots status",
}


@dataclass
class SensitivityResult:
    label: str
    confidence: float
    rationale: str


def _normalize_path(path: str) -> str:
    segments = [segment for segment in TOKEN_SPLIT.split(path.lower()) if segment]
    expanded = []
    for segment in segments:
        expanded.extend(ABBREVIATIONS.get(segment, segment).split())
    return " ".join(expanded)


def _token_score(text: str, anchor: str) -> float:
    text_tokens = set(text.split())
    anchor_tokens = set(anchor.split())
    if not text_tokens or not anchor_tokens:
        return 0.0
    overlap = len(text_tokens & anchor_tokens)
    union = len(text_tokens | anchor_tokens)
    return overlap / union


def classify_endpoint(path: str) -> SensitivityResult:
    normalized = _normalize_path(path)
    scores = {label: _token_score(normalized, anchor) for label, anchor in ANCHORS.items()}
    best_label = max(scores, key=scores.get)
    best_score = scores[best_label]

    if best_score == 0:
        if any(token in normalized for token in ("login", "auth", "user", "account")):
            return SensitivityResult("HIGH", 0.74, "keyword match for identity-related path")
        if any(token in normalized for token in ("public", "static", "assets", "docs")):
            return SensitivityResult("LOW", 0.81, "keyword match for low-risk public content")
        return SensitivityResult("MEDIUM", 0.55, "default middle-risk classification")

    confidence = min(0.98, 0.6 + math.sqrt(best_score))
    return SensitivityResult(best_label, round(confidence, 2), f"semantic match against {best_label.lower()} anchor")
