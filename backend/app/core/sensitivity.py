"""Endpoint sensitivity classifier.

Design: a **hybrid** classifier.

* A deterministic keyword/token layer produces the *explainable reasons* and a
  category signal. This is what makes the output defensible in a viva: every
  classification says *why*.
* An optional sentence-transformer layer (``all-MiniLM-L6-v2``) adds semantic
  cosine-similarity to per-class anchor phrases, blended into the confidence.

The embedding model is loaded lazily and is entirely optional: if
``sentence-transformers`` / ``torch`` are not installed, the classifier falls
back to the keyword layer alone. The core scanner therefore never depends on a
GPU or a heavy model download.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.db.models.enums import ContextClass
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Abbreviation expansion so short path tokens match keyword families.
_ABBREVIATIONS = {
    "usr": "user",
    "auth": "authentication",
    "priv": "privilege",
    "iam": "identity access management",
    "admin": "administrator",
    "pay": "payment",
    "acct": "account",
    "cfg": "config",
    "svc": "service",
    "mfa": "multi factor authentication",
    "sso": "single sign on",
    "pwd": "password",
    "cred": "credential",
    "txn": "transaction",
    "creds": "credentials",
    "ms": "microservice",
}

# Token families -> (class, human reason). Order = priority (CRITICAL first).
# Tiers are calibrated to the spec's worked examples: identity/privilege/
# payment/secrets => CRITICAL; auth-flow/user/session => HIGH.
_KEYWORD_RULES: list[tuple[ContextClass, str, set[str]]] = [
    (
        ContextClass.CRITICAL,
        "Contains identity/privilege tokens",
        {
            "identity",
            "iam",
            "privilege",
            "escalate",
            "escalation",
            "root",
            "sudo",
            "grant",
            "administrator",
            "admin",
        },
    ),
    (
        ContextClass.CRITICAL,
        "Contains payment/financial tokens",
        {
            "payment",
            "billing",
            "checkout",
            "stripe",
            "card",
            "invoice",
            "charge",
            "refund",
            "wallet",
            "bank",
        },
    ),
    (
        ContextClass.CRITICAL,
        "Contains secret/credential tokens",
        {"secret", "credential", "credentials", "password", "apikey", "privatekey"},
    ),
    (
        ContextClass.HIGH,
        "Contains authentication/session tokens",
        {
            "authentication",
            "login",
            "signin",
            "logout",
            "sso",
            "oauth",
            "multi",
            "factor",
            "otp",
            "verify",
            "confirm",
            "reset",
            "session",
            "token",
        },
    ),
    (
        ContextClass.HIGH,
        "Contains user/account tokens",
        {"user", "account", "profile", "customer", "member", "email"},
    ),
    (
        ContextClass.MEDIUM,
        "Contains generic API/data tokens",
        {
            "api",
            "data",
            "search",
            "query",
            "upload",
            "download",
            "report",
            "config",
            "settings",
            "order",
            "product",
            "service",
        },
    ),
    (
        ContextClass.LOW,
        "Public/informational path",
        {
            "about",
            "public",
            "home",
            "index",
            "static",
            "assets",
            "help",
            "faq",
            "contact",
            "terms",
            "privacy",
            "docs",
            "blog",
            "news",
        },
    ),
]

# Short names for the families, as checks.yaml refers to them
# (applies_to.sensitivity_family).
FAMILY_NAMES = {
    "Contains identity/privilege tokens": "identity",
    "Contains payment/financial tokens": "payment",
    "Contains secret/credential tokens": "secrets",
    "Contains authentication/session tokens": "authentication",
    "Contains user/account tokens": "account",
    "Contains generic API/data tokens": "api",
    "Public/informational path": "public",
}

_CLASS_RANK = {
    ContextClass.LOW: 0,
    ContextClass.MEDIUM: 1,
    ContextClass.HIGH: 2,
    ContextClass.CRITICAL: 3,
}

# Anchor phrases per class for the optional embedding layer.
_ANCHORS = {
    ContextClass.CRITICAL: "authentication login admin privilege payment secret credential",
    ContextClass.HIGH: "user account profile verification session",
    ContextClass.MEDIUM: "api data search report configuration",
    ContextClass.LOW: "public about home static help documentation",
}


@dataclass
class ClassificationResult:
    context_class: ContextClass
    confidence: float
    reason: list[str] = field(default_factory=list)
    # Every keyword family the path matched, not only the winning class's
    # (/admin/login is CRITICAL and still an authentication endpoint).
    families: frozenset[str] = frozenset()

    def as_dict(self) -> dict:
        """This classification result as a plain dict."""
        return {
            "class": self.context_class.value,
            "confidence": round(self.confidence, 2),
            "reason": self.reason,
        }


def raw_tokens(path: str) -> list[str]:
    """Split a URL path into raw lowercase tokens (before expansion)."""
    out: list[str] = []
    for t in re.split(r"[/\-_.?=&]+", path.lower()):
        if t and not t.isdigit():
            out.append(t)
    return out


def _tokenize(path: str, extra_expansions: dict[str, str] | None = None) -> list[str]:
    """Split a URL path into normalized, abbreviation-expanded tokens.

    ``extra_expansions`` (e.g. produced by an LLM) take priority over the
    built-in abbreviation table; unknown tokens pass through unchanged.
    """
    extra = extra_expansions or {}
    tokens: list[str] = []
    for t in raw_tokens(path):
        expanded = extra.get(t) or _ABBREVIATIONS.get(t, t)
        tokens.extend(str(expanded).split())
    return tokens


def _family_match(tokens: set[str], family: set[str]) -> bool:
    """A family keyword matches a token exactly, or as a substring (len>=4)."""
    if tokens & family:
        return True
    for kw in family:
        if len(kw) >= 4 and any(kw in tok for tok in tokens):
            return True
    return False


class SensitivityClassifier:
    """Classify an endpoint path into CRITICAL/HIGH/MEDIUM/LOW."""

    def __init__(self, use_embeddings: bool = True) -> None:
        """Set up the classifier; optionally load the embedding model."""
        self._model: Any = None
        self._anchor_vecs: dict[ContextClass, Any] | None = None
        self._embeddings_ok = False
        if use_embeddings:
            self._try_load_model()

    def _try_load_model(self) -> None:
        """Try to load the embedding model; fall back to keywords."""
        try:
            from sentence_transformers import SentenceTransformer  # heavy, optional

            self._model = SentenceTransformer("all-MiniLM-L6-v2")
            self._anchor_vecs = {
                cls: self._model.encode(text, normalize_embeddings=True)
                for cls, text in _ANCHORS.items()
            }
            self._embeddings_ok = True
            logger.info("sensitivity: embedding model loaded")
        except Exception as exc:  # noqa: BLE001 - model is optional
            logger.info("sensitivity: embeddings unavailable, keyword-only (%s)", exc)
            self._embeddings_ok = False

    @property
    def embeddings_available(self) -> bool:
        """True if the embedding model loaded."""
        return self._embeddings_ok

    def classify(
        self, path: str, extra_expansions: dict[str, str] | None = None
    ) -> ClassificationResult:
        """Return class + confidence + explainable reasons for a path.

        ``extra_expansions`` is an optional {token: full_form} map (e.g. from an
        LLM) applied before keyword matching; without it the built-in
        abbreviation table is used.
        """
        tokens = set(_tokenize(path, extra_expansions))

        # Keyword layer (authoritative for the reasons)
        matched: list[tuple[ContextClass, str]] = []
        for cls, reason, family in _KEYWORD_RULES:
            if _family_match(tokens, family):
                matched.append((cls, reason))

        families = frozenset(FAMILY_NAMES[r] for _, r in matched)
        if matched:
            best_cls = max((c for c, _ in matched), key=lambda c: _CLASS_RANK[c])
            reasons = [r for c, r in matched if c == best_cls]
            kw_conf = 0.6 + 0.1 * min(len(reasons), 3)  # 0.6-0.9
        else:
            best_cls = ContextClass.LOW
            reasons = ["No sensitive tokens detected; treated as low-sensitivity"]
            kw_conf = 0.5

        # Optional embedding layer (blends confidence)
        if self._embeddings_ok and self._model is not None:
            try:
                import numpy as np

                vec = self._model.encode(
                    " ".join(_tokenize(path, extra_expansions)) or "root",
                    normalize_embeddings=True,
                )
                sims = {
                    cls: float(np.dot(vec, av))
                    for cls, av in self._anchor_vecs.items()  # type: ignore[union-attr]
                }
                emb_cls = max(sims, key=lambda c: sims[c])
                emb_conf = max(0.0, sims[emb_cls])
                # Blend: keep keyword class, average the confidences; if the
                # embedding agrees, confidence rises.
                agree = emb_cls == best_cls
                confidence = min(0.99, (kw_conf + emb_conf) / 2 + (0.1 if agree else 0))
                if agree:
                    reasons.append("Semantic similarity agrees with keyword signal")
                return ClassificationResult(best_cls, confidence, reasons, families)
            except Exception as exc:  # noqa: BLE001
                logger.debug("embedding step skipped: %s", exc)

        return ClassificationResult(best_cls, kw_conf, reasons, families)


# A module-level default instance (embeddings loaded if available).
_default: SensitivityClassifier | None = None


def get_classifier() -> SensitivityClassifier:
    """The shared built-in sensitivity classifier (cached)."""
    global _default
    if _default is None:
        _default = SensitivityClassifier(use_embeddings=True)
    return _default
