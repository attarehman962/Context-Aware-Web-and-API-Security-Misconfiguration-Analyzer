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
from app.core.contracts import EndpointInfo, ResponseInfo
from app.core.engine import ScanResponse
from app.core.specs import CheckSpec, load_checks
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


def register_check(check_id: str) -> Callable[[CheckFn], CheckFn]:
    """Register the decorated function as the implementation of ``check_id``."""
    if not _CHECK_ID.match(check_id):
        raise RegistryError(f"{check_id!r} is not a valid check_id (AAA-NNN)")

    def decorate(fn: CheckFn) -> CheckFn:
        if check_id in CHECKS:
            raise RegistryError(f"{check_id} registered twice "
                                f"({CHECKS[check_id].__module__} and {fn.__module__})")
        CHECKS[check_id] = fn
        return fn

    return decorate


# ------------------------------------------------------------------- specs

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
        logger.warning("checks.yaml: %d spec(s) with no implementation yet: %s",
                       len(missing), ", ".join(missing))
    return missing


def validate_registry_at_startup() -> None:
    load_implementations()
    validate_registry(load_specs())


# ------------------------------------------------------------------ running

def response_info(resp: ScanResponse) -> ResponseInfo:
    return ResponseInfo(url=resp.final_url, status_code=resp.status_code or 0,
                        content_type=resp.content_type, headers=resp.headers, body=resp.body)


def condition_matches(check_id: str, resp: ScanResponse, *,
                      headers: Mapping[str, str] | None = None) -> bool:
    """Whether the spec's http_condition holds for ``resp`` (method included).

    ``headers`` replaces the response headers, e.g. one ``Set-Cookie`` at a time:
    the engine folds repeated headers, so a cookie check must see each cookie.
    """
    condition = spec_for(check_id).http_condition
    info = response_info(resp)
    if headers is not None:
        info = ResponseInfo(url=info.url, status_code=info.status_code,
                            content_type=info.content_type, headers=headers, body=info.body)
    return resp.method == condition.method and condition.matches(info)


def run_spec_checks(resp: ScanResponse, endpoint: EndpointInfo, *,
                    scope: str = "every_endpoint") -> list[RawFinding]:
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
            findings.extend(CHECKS[check_id](resp, endpoint))
        except Exception as exc:  # noqa: BLE001 - one bad check must not stop the scan
            logger.warning("check %s raised on %s: %s", check_id, endpoint.url, exc)
    return findings
