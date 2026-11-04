"""Endpoint sensitivity classifier (owner: Asim).

Keeps the signature from docs/cvss-mapping-contract.md and delegates to the
built-in keyword/embedding classifier (``app.core.sensitivity``), with one rule
in front of it: a static asset (stylesheet, script, image, font, source map) is
LOW whatever its name says. ``/dvwa/css/login.css`` was classed as sensitive
because of "login", so a missing Cache-Control on a stylesheet was reported as
a sensitive-endpoint finding (HDR-011). Found on the dev split
(docs/evaluation-method.md); the labelling guide already excludes static files.
"""
from __future__ import annotations

from app.core.contracts import EndpointInfo, SensitivityClass, builtin_classify

STATIC_SUFFIXES = (".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                   ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".otf")


def is_static_asset(path: str) -> bool:
    return path.split("?", 1)[0].lower().endswith(STATIC_SUFFIXES)


def classify(endpoint: EndpointInfo) -> SensitivityClass:
    """Sensitivity class of ``endpoint``. Must not raise (contract rule 1)."""
    try:
        if is_static_asset(endpoint.path):
            return SensitivityClass.LOW
    except Exception:  # noqa: BLE001 - contract: fall through to the built-in classifier
        pass
    return builtin_classify(endpoint)
