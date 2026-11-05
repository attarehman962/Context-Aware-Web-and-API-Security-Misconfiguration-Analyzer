"""Endpoint sensitivity classifier (owner: Asim; Prompt 6).

``classify(endpoint) -> SensitivityClass``, the signature from
docs/cvss-mapping-contract.md. Two rules come first, then one of two classifiers:

1. A static asset (stylesheet, script, image, font, source map) is LOW whatever
   its name says. ``/dvwa/css/login.css`` was classed as sensitive because of
   "login", so a missing Cache-Control on a stylesheet was reported as a
   sensitive-endpoint finding (HDR-011; dev split, docs/evaluation-method.md).
2. With ``enabled: true`` in ``config/sensitivity_anchors.yaml`` and
   sentence-transformers installed: the **anchor classifier**. The path becomes
   text (split on ``/ - _ .`` and camelCase, IDs dropped, abbreviations
   expanded, method in front), is embedded with all-MiniLM-L6-v2 and compared
   with each class's anchor phrases (cosine, best anchor per class). Below the
   threshold the path gets the file's ``default_class``.
3. Otherwise the built-in keyword/embedding classifier (``app.core.sensitivity``),
   which the final evaluation tables were produced with.

Whatever happens, ``classify`` returns a class and never raises (contract rule 1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.config import settings
from app.core.contracts import EndpointInfo, SensitivityClass, builtin_classify
from app.utils.logging import get_logger

logger = get_logger(__name__)

STATIC_SUFFIXES = (
    ".css",
    ".js",
    ".mjs",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
)

_ID = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|[0-9a-f]{24}|[0-9a-f]{32,}|v\d+|:\w+|\{\w+\})$",
    re.I,
)
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def is_static_asset(path: str) -> bool:
    return path.split("?", 1)[0].lower().endswith(STATIC_SUFFIXES)


@dataclass(frozen=True)
class AnchorConfig:
    enabled: bool = False
    model: str = "all-MiniLM-L6-v2"
    threshold: float = 0.30
    default_class: SensitivityClass = SensitivityClass.MEDIUM
    abbreviations: dict[str, str] = field(default_factory=dict)
    anchors: dict[SensitivityClass, tuple[str, ...]] = field(default_factory=dict)


def load_config(path: Path | None = None) -> AnchorConfig:
    path = path or Path(settings.CONFIG_DIR) / "sensitivity_anchors.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    anchors = {
        SensitivityClass(c): tuple(str(p) for p in phrases)
        for c, phrases in (data.get("anchors") or {}).items()
    }
    if set(anchors) != set(SensitivityClass) or not all(anchors.values()):
        raise ValueError(f"{path}: every class needs at least one anchor phrase")
    return AnchorConfig(
        enabled=bool(data.get("enabled", False)),
        model=str(data.get("model", "all-MiniLM-L6-v2")),
        threshold=float(data.get("threshold", 0.30)),
        default_class=SensitivityClass(data.get("default_class", "MEDIUM")),
        abbreviations={
            str(k).lower(): str(v) for k, v in (data.get("abbreviations") or {}).items()
        },
        anchors=anchors,
    )


def path_text(path: str, method: str = "GET", abbreviations: dict[str, str] | None = None) -> str:
    """``/api/v1/userAccounts/42/pwd-reset`` -> ``GET api user accounts password reset``."""
    words = []
    for segment in path.split("?", 1)[0].split("/"):
        if not segment or _ID.match(segment):
            continue
        for part in re.split(r"[-_.]+", segment):
            for word in _CAMEL.sub(" ", part).lower().split():
                if word.isdigit():
                    continue
                words.append((abbreviations or {}).get(word, word))
    return " ".join([method.upper(), *(words or ["home page"])])


class AnchorClassifier:
    """Embeds the anchors once; each ``classify`` embeds one path."""

    def __init__(self, config: AnchorConfig, model: Any = None) -> None:
        self.config = config
        if model is None:
            from sentence_transformers import SentenceTransformer

            model = SentenceTransformer(config.model)
        self._model = model
        self._classes = list(config.anchors)
        self._anchor_class: list[SensitivityClass] = []
        phrases: list[str] = []
        for cls in self._classes:
            for phrase in config.anchors[cls]:
                self._anchor_class.append(cls)
                phrases.append(phrase)
        self._anchors = model.encode(phrases, normalize_embeddings=True)

    def scores(self, path: str, method: str = "GET") -> dict[SensitivityClass, float]:
        text = path_text(path, method, self.config.abbreviations)
        vec = self._model.encode([text], normalize_embeddings=True)[0]
        best: dict[SensitivityClass, float] = {}
        for cls, anchor in zip(self._anchor_class, self._anchors, strict=True):
            sim = float(sum(a * b for a, b in zip(anchor, vec, strict=True)))  # unit vectors
            best[cls] = max(best.get(cls, -1.0), sim)
        return best

    def classify(self, path: str, method: str = "GET") -> SensitivityClass:
        scores = self.scores(path, method)
        cls, score = max(scores.items(), key=lambda kv: kv[1])
        if score < self.config.threshold:
            logger.info(
                "sensitivity: %s %s below threshold (%.2f < %.2f): %s",
                method,
                path,
                score,
                self.config.threshold,
                self.config.default_class.value,
            )
            return self.config.default_class
        return cls


@lru_cache(maxsize=1)
def anchor_classifier() -> AnchorClassifier | None:
    """The anchor classifier, or None when it is off or can't load (no ML deps,
    no model, bad config); then the built-in classifier is used."""
    try:
        config = load_config()
        if not config.enabled:
            return None
        return AnchorClassifier(config)
    except Exception as exc:  # noqa: BLE001 - optional: fall back to the built-in
        logger.warning("sensitivity: anchor classifier unavailable (%s); using keywords", exc)
        return None


def classify(endpoint: EndpointInfo) -> SensitivityClass:
    """Sensitivity class of ``endpoint``. Must not raise (contract rule 1)."""
    try:
        if is_static_asset(endpoint.path):
            return SensitivityClass.LOW
        model = anchor_classifier()
        if model is not None:
            return model.classify(endpoint.path, endpoint.method or "GET")
    except Exception:  # noqa: BLE001 - contract: fall through to the built-in classifier
        logger.exception("sensitivity: anchor classifier failed for %s", endpoint.path)
    return builtin_classify(endpoint)
