"""Spec-driven check registry (docs/adding-a-check.md).

Each check in Asim's ``config/checks.yaml`` gets one implementation, registered
with :func:`register_check` in a module under ``app/core/checks/spec/`` (one
file per check family; every module there is imported automatically). A check
takes the normalised :class:`~app.core.engine.ScanResponse` and the
:class:`~app.core.contracts.EndpointInfo`, and returns :class:`RawFinding`
objects: what fired, where, and the redacted evidence. Scoring happens later
in ``cvss.py``; a check never computes a score.

At startup :func:`validate_registry_at_startup` cross-checks the registry with
``checks.yaml``: a spec without an implementation is logged as a warning, an
implementation without a spec stops the process.

The 58 rules in the older ``@rule`` catalog (``base.py``, ``headers.py``, ...)
keep running unchanged until each is moved here.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.config import settings
from app.core.contracts import EndpointInfo, ResponseInfo, SensitivityClass
from app.core.engine import ScanResponse
from app.core.specs import AppliesToRule, CheckSpec, load_checks
from app.utils.logging import get_logger

logger = get_logger(__name__)

_CHECK_ID = re.compile(r"^[A-Z]{3}-\d{3}$")


class RegistryError(RuntimeError):
    """The registry and checks.yaml disagree, or a check was registered badly."""


@dataclass(frozen=True)
class RawFinding:
    """A check fired. ``evidence`` is redacted JSON with at least a ``text`` key."""

    check_id: str
    endpoint: EndpointInfo
    evidence: dict[str, Any] = field(default_factory=dict)


CheckFn = Callable[[ScanResponse, EndpointInfo], list[RawFinding]]
CHECKS: dict[str, CheckFn] = {}


@dataclass(frozen=True)
class SoftNotFound:
    """What the host answers for a path that can't exist (one random path per
    scan, fetched by the crawler). A response like it is the site's catch-all,
    not the file a check is looking for."""

    path: str
    status_code: int | None
    body: str

    def matches(self, resp: ScanResponse, path: str) -> bool:
        if resp.status_code != self.status_code:
            return False
        # A 404 page may quote the path it was asked for.
        return resp.body.replace(path, "") == self.body.replace(self.path, "")


@dataclass(frozen=True)
class SpecContext:
    """What the pipeline knows about the endpoint beyond its response, for the
    ``applies_to`` and ``artifact`` blocks of a spec."""

    sensitivity: SensitivityClass | None = None
    families: frozenset[str] = frozenset()
    passive: bool = False
    soft_404: SoftNotFound | None = None


def register_check(check_id: str) -> Callable[[CheckFn], CheckFn]:
    """Register the decorated function as the implementation of ``check_id``."""
    if not _CHECK_ID.match(check_id):
        raise RegistryError(f"{check_id!r} is not a valid check_id (AAA-NNN)")

    def decorate(fn: CheckFn) -> CheckFn:
        if check_id in CHECKS:
            raise RegistryError(
                f"{check_id} registered twice "
                f"({CHECKS[check_id].__module__} and {fn.__module__})"
            )
        CHECKS[check_id] = fn
        return fn

    return decorate


# Specs


@lru_cache
def _specs_from(path: str) -> Mapping[str, CheckSpec]:
    return {c.check_id: c for c in load_checks(path).checks}


def load_specs(path: Path | str | None = None) -> Mapping[str, CheckSpec]:
    return _specs_from(str(path or Path(settings.CONFIG_DIR) / "checks.yaml"))


def spec_for(check_id: str) -> CheckSpec:
    return load_specs()[check_id]


def load_implementations() -> None:
    """Import every module in app/core/checks/spec/ so its checks register."""
    from app.core.checks import spec as package

    for module in pkgutil.iter_modules(package.__path__):
        importlib.import_module(f"{package.__name__}.{module.name}")


def validate_registry(specs: Mapping[str, CheckSpec] | Iterable[str]) -> list[str]:
    """Fail on implementations without a spec; return (and log) specs without one."""
    spec_ids = set(specs)
    orphans = sorted(set(CHECKS) - spec_ids)
    if orphans:
        raise RegistryError(f"implemented but not in checks.yaml: {', '.join(orphans)}")
    missing = sorted(spec_ids - set(CHECKS))
    if missing:
        logger.warning(
            "checks.yaml: %d spec(s) with no implementation yet: %s",
            len(missing),
            ", ".join(missing),
        )
    return missing


def validate_registry_at_startup() -> None:
    load_implementations()
    validate_registry(load_specs())


# Running


def response_info(resp: ScanResponse) -> ResponseInfo:
    return ResponseInfo(
        url=resp.final_url,
        status_code=resp.status_code or 0,
        content_type=resp.content_type,
        headers=resp.headers,
        body=resp.body,
    )


def condition_matches(
    check_id: str, resp: ScanResponse, *, headers: Mapping[str, str] | None = None
) -> bool:
    """Whether the spec's http_condition holds for ``resp`` (method included).

    ``headers`` replaces the response headers, e.g. one ``Set-Cookie`` at a time:
    the engine folds repeated headers, so a cookie check must see each cookie.
    """
    condition = spec_for(check_id).http_condition
    info = response_info(resp)
    if headers is not None:
        info = ResponseInfo(
            url=info.url,
            status_code=info.status_code,
            content_type=info.content_type,
            headers=headers,
            body=info.body,
        )
    return resp.method == condition.method and condition.matches(info)


_HTML = re.compile(r"(?is)\A\s*(?:<!doctype html|<html)")
_CREDENTIAL_HEADERS = ("authorization", "cookie")


def _rule_holds(
    rule: AppliesToRule, resp: ScanResponse, endpoint: EndpointInfo, context: SpecContext
) -> bool:
    if rule.sensitivity is not None:
        return context.sensitivity in rule.sensitivity
    if rule.sensitivity_family is not None:
        return rule.sensitivity_family in context.families
    if rule.path is not None:
        return re.search(rule.path, endpoint.path) is not None and (
            rule.methods is None or endpoint.method.upper() in rule.methods
        )
    sent = {k.lower() for k in resp.request_headers}  # credentials: absent
    return not sent & set(_CREDENTIAL_HEADERS)


def applies(
    spec: CheckSpec, resp: ScanResponse, endpoint: EndpointInfo, context: SpecContext | None
) -> bool:
    """Whether ``spec`` judges this endpoint at all (its applies_to and artifact
    blocks); http_condition then decides whether it fires. A spec with either
    block needs a context; without one (host-level runs) it is not judged."""
    if spec.applies_to is None and spec.artifact is None:
        return True
    if context is None:
        return False
    art = spec.artifact
    if art is not None:
        if context.passive or not re.search(art.path, endpoint.path):
            return False
        if art.not_html and ("html" in (resp.content_type or "").lower() or _HTML.match(resp.body)):
            return False
        if art.not_soft_404 and context.soft_404 and context.soft_404.matches(resp, endpoint.path):
            return False
        if art.require_body and not (resp.body.strip() or resp.content_length):
            return False
    if spec.applies_to is not None:
        held = (_rule_holds(r, resp, endpoint, context) for r in spec.applies_to.rules)
        if not (all(held) if spec.applies_to.match == "all" else any(held)):
            return False
    return True


def artifact_probe_paths() -> list[str]:
    """The fixed paths the artifact specs ask to probe, for the crawler."""
    return sorted(
        {p for spec in load_specs().values() if spec.artifact for p in spec.artifact.probe}
    )


def run_check(
    check_id: str, resp: ScanResponse, endpoint: EndpointInfo, context: SpecContext | None = None
) -> list[RawFinding]:
    """One check, through its applies_to / artifact gate."""
    if not applies(spec_for(check_id), resp, endpoint, context):
        return []
    return CHECKS[check_id](resp, endpoint)


def run_spec_checks(
    resp: ScanResponse,
    endpoint: EndpointInfo,
    *,
    scope: str = "every_endpoint",
    context: SpecContext | None = None,
) -> list[RawFinding]:
    """Run every registered check of ``scope`` on this response. The pipeline
    calls it for each endpoint's GET and CORS preflight (``every_endpoint``),
    and once per host for the plain-HTTP probe (``target_root``). One failing
    check is logged and skipped; it never stops the others."""
    findings: list[RawFinding] = []
    for check_id in sorted(CHECKS):
        spec = load_specs().get(check_id)
        if spec is None or spec.http_condition.scope != scope:
            continue
        try:
            findings.extend(run_check(check_id, resp, endpoint, context))
        except Exception as exc:  # noqa: BLE001 - one bad check must not stop the scan
            logger.warning("check %s raised on %s: %s", check_id, endpoint.url, exc)
    return findings
