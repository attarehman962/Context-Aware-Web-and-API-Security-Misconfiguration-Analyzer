"""Attack-chain correlation -- Contribution 2 (docs/chain-templates.md).

Templates come from Asim's ``config/chains.yaml`` (format 1.1). For each
template and each scope unit (one endpoint, one host, or the whole scan) a
chain fires when **every** group has at least one member finding in the unit,
and the unit passes the template's ``endpoint_sensitivity`` and
``body_signals`` gates. It fires at most once per template per unit.

Host-level findings (no endpoint, e.g. TLS-005) belong to their host and to
every endpoint on it. For a ``same_host`` chain, ``endpoint_sensitivity`` is
satisfied by **any** endpoint of the host (the login page is what makes a
missing HSTS on ``/`` dangerous); for ``same_endpoint`` it is the endpoint
itself. A chain is reported only when its members are actually present --
never speculatively -- and scores with its own CVSS v3.1 composite vector,
which the spec validator guarantees is above every member (SRS O4).

Database-free: inputs and outputs are plain dataclasses.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.config import settings
from app.core.contracts import BodySignal, SensitivityClass
from app.core.specs import ChainSpec, load_chains
from app.db.models.enums import Severity


@dataclass(frozen=True)
class ChainEndpoint:
    url: str
    sensitivity: SensitivityClass | None
    body_signals: frozenset[BodySignal] = frozenset()

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc.lower()


@dataclass(frozen=True)
class ChainMember:
    """A finding as the correlator sees it: its check and where it is."""

    check_id: str
    endpoint_index: int | None        # None: host-level (belongs to ``host``)
    host: str = ""


@dataclass
class DetectedChain:
    code: str
    name: str
    description: str
    composite_score: float
    severity: Severity
    composite_vector: str | None
    member_indexes: list[int] = field(default_factory=list)   # indexes into the findings
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def matched_rule_ids(self) -> list[str]:          # kept for existing callers
        return sorted({c for g in self.evidence.get("groups", []) for c in g})


@lru_cache(maxsize=4)
def _templates(path: str) -> tuple[ChainSpec, ...]:
    return tuple(load_chains(path).chains)


def load_templates(path: Path | str | None = None) -> tuple[ChainSpec, ...]:
    return _templates(str(path or Path(settings.CONFIG_DIR) / "chains.yaml"))


def _units(spec: ChainSpec, members: Sequence[ChainMember],
           endpoints: Sequence[ChainEndpoint]) -> list[tuple[str, str, list[int], list[int]]]:
    """(kind, value, member indexes in the unit, endpoint indexes of the unit)."""
    hosts = sorted({ep.host for ep in endpoints} | {m.host for m in members if m.host})
    if spec.scope == "any_endpoint":
        return [("scan", "*", list(range(len(members))), list(range(len(endpoints))))]
    if spec.scope == "same_host":
        out = []
        for host in hosts:
            eps = [i for i, ep in enumerate(endpoints) if ep.host == host]
            ms = [i for i, m in enumerate(members)
                  if (m.endpoint_index in eps) or (m.endpoint_index is None and m.host == host)]
            out.append(("host", host, ms, eps))
        return out
    out = []
    for e, ep in enumerate(endpoints):                 # same_endpoint
        ms = [i for i, m in enumerate(members)
              if m.endpoint_index == e or (m.endpoint_index is None and m.host == ep.host)]
        out.append(("endpoint", ep.url, ms, [e]))
    return out


def correlate(members: Sequence[ChainMember], endpoints: Sequence[ChainEndpoint],
              templates: Sequence[ChainSpec] | None = None) -> list[DetectedChain]:
    """Chains whose conditions hold, in template order, once per template per unit."""
    detected: list[DetectedChain] = []
    for spec in templates if templates is not None else load_templates():
        groups = spec.groups or [list(spec.requires or [])]
        for kind, value, unit_members, unit_endpoints in _units(spec, members, endpoints):
            matched = [[i for i in unit_members if members[i].check_id in group]
                       for group in groups]
            if any(not hits for hits in matched):
                continue
            context: dict[str, Any] = {}
            if spec.endpoint_sensitivity:
                classes = {endpoints[e].sensitivity for e in unit_endpoints} & set(
                    spec.endpoint_sensitivity)
                if not classes:
                    continue
                context["endpoint_sensitivity"] = sorted(c.value for c in classes if c)
            member_ids = sorted({i for hits in matched for i in hits})
            if spec.body_signals:
                shown: set[BodySignal] = set()
                for i in member_ids:
                    idx = members[i].endpoint_index
                    if idx is not None:
                        shown |= endpoints[idx].body_signals
                hit = shown & set(spec.body_signals)
                if not hit:
                    continue
                context["body_signals"] = sorted(s.value for s in hit)
            detected.append(DetectedChain(
                code=spec.chain_id, name=spec.name, description=spec.description,
                composite_score=spec.score, severity=spec.severity,
                composite_vector=spec.composite_cvss_vector, member_indexes=member_ids,
                evidence={
                    "scope": {"kind": kind, "value": value},
                    "groups": [sorted({members[i].check_id for i in hits}) for hits in matched],
                    "context": context,
                    "composite_cvss_vector": spec.composite_cvss_vector,
                },
            ))
    return detected
