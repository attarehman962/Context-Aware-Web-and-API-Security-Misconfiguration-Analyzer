"""Public API contract v1: the shapes Neelam's frontend builds against.

Frozen at the end of Sprint 1 (docs/api-contract.md). Rules for changing it:

* adding an optional response field or a new endpoint is a MINOR bump
  (1.0.0 -> 1.1.0) and must keep every existing field;
* renaming/removing a field, changing a type or an enum value is a MAJOR bump
  and needs Neelam's agreement first;
* bump :data:`CONTRACT_VERSION`, run ``make openapi`` and note it in the
  changelog of docs/api-contract.md.

Importable as ``from app.api.schemas import ScanRequest, ...``.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.contracts import BodySignal, SensitivityClass
from app.db.models.enums import FindingCategory, Severity
from app.db.models.enums import ScanStatus as ScanState

CONTRACT_VERSION = "1.2.0"

__all__ = [
    "CONTRACT_VERSION",
    "ExportFormat",
    "Finding",
    "FindingDetail",
    "EndpointDetail",
    "FindingsMeta",
    "Chain",
    "ScanOptions",
    "ScanRequest",
    "ScanResults",
    "ScanState",
    "ScanStatus",
    "SeverityCounts",
]

ExportFormat = Literal["json", "csv", "html", "pdf"]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanOptions(_Contract):
    """How a scan runs. Stored on the scan and echoed back in ScanStatus."""

    crawl_depth: int = Field(2, ge=1, le=2, description="Link-following depth from the URL.")
    use_wordlist: bool = Field(True, description="Probe a bounded list of common paths "
                                                 "(e.g. /.env, /admin).")
    passive_only: bool = Field(False, description="No active probes (TLS probe, rate-limit "
                                                  "burst, redirect check): only observe "
                                                  "normal GET responses.")


class ScanRequest(ScanOptions):
    """Body of ``POST /api/scan``."""

    url: str = Field(..., min_length=1, max_length=2048,
                     examples=["https://shop.example.com"],
                     description="HTTPS URL to scan. Must resolve to a public address.")
    authorisation_confirmed: Literal[True] = Field(
        ..., description="Must be true: the user confirms they are authorised to test "
                         "this target. Requests without it are rejected (422).",
    )


class SeverityCounts(_Contract):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanStatus(_Contract):
    """One scan's state. Returned by ``POST /api/scan``, inside ``ScanResults``
    and as the items of ``GET /api/scans``."""

    scan_id: uuid.UUID
    url: str
    status: ScanState = Field(..., description="QUEUED -> RUNNING -> DONE | FAILED")
    progress: int = Field(..., ge=0, le=100)
    stage: str | None = Field(None, examples=["crawling"],
                              description="Human-readable current step; display only.")
    options: ScanOptions
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = Field(None, description="Why the scan failed (status FAILED).")
    severity_counts: SeverityCounts = Field(default_factory=SeverityCounts)


class Finding(_Contract):
    id: uuid.UUID
    check_id: str = Field(..., examples=["HDR-001"])
    title: str
    category: FindingCategory
    endpoint_id: uuid.UUID | None = Field(None, description="Null for host-level findings "
                                                            "(e.g. TLS).")
    endpoint_url: str | None = None
    owasp_map: list[str] = Field(..., examples=[["API8:2023"]])
    cwe_map: list[str] = Field(..., examples=[["CWE-319"]])
    cvss_vector: str = Field(..., examples=["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"])
    base_score: float = Field(..., ge=0, le=10, description="Official CVSS v3.1 base score.")
    final_score: float = Field(..., ge=0, le=10,
                               description="CAWASMA context-aware score (not official CVSS).")
    final_vector: str | None = Field(
        None, examples=["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/CR:M/IR:M/AR:L"],
        description="Since 1.1. The base vector plus the CR/IR/AR environmental requirements "
                    "final_score was computed from (CVSS v3.1 environmental score). Null for "
                    "findings still scored by the interim formula.")
    score_reasons: list[str] = Field(
        default_factory=list, examples=[["sensitivity:LOW", "no-context-change",
                                         "base:5.9", "environmental:5.9"]],
        description="Since 1.1. Why each requirement was set; empty when final_vector is null.")
    severity_bucket: Severity
    evidence: dict[str, Any] = Field(..., description="Redacted. Always has 'text'; other "
                                                      "keys depend on the check.")
    # Drill-down context
    sensitivity_class: SensitivityClass | None = Field(
        None, description="Sensitivity class of the endpoint (null for host-level findings).")
    body_signals: list[BodySignal] = Field(
        default_factory=list, description="Sensitive data seen in the endpoint's response.")
    chain_ids: list[uuid.UUID] = Field(default_factory=list,
                                       description="Ids of chains in ScanResults.chains "
                                                   "this finding belongs to.")
    recommendation: str | None = None
    limitation: str | None = Field(None, description="Set when black-box testing cannot "
                                                     "confirm the finding; show it.")


class Chain(_Contract):
    id: uuid.UUID
    chain_code: str = Field(..., examples=["C005"])
    name: str
    description: str | None = None
    composite_score: float = Field(..., ge=0, le=10,
                                   description="CVSS v3.1 base score of composite_vector "
                                               "(always above every member's score).")
    severity: Severity
    finding_ids: list[uuid.UUID]
    composite_vector: str | None = Field(
        None, examples=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"],
        description="Since 1.2. The chain's own CVSS v3.1 vector (config/chains.yaml).")
    evidence: dict[str, Any] | None = Field(
        None, description="Since 1.2. Why it fired: scope (kind, value), the matched "
                          "check ids per group, and the context (sensitivity class or body "
                          "signal) that satisfied the template.")


class FindingsMeta(_Contract):
    """Since 1.2: what the findings list holds after filters and pagination."""

    total: int = Field(..., ge=0, description="Findings matching the filters (all pages).")
    page: int | None = Field(None, ge=1, description="Null when not paginated.")
    limit: int | None = Field(None, ge=1)
    pages: int | None = Field(None, ge=0)
    filters: dict[str, Any] = Field(default_factory=dict,
                                    description="The filters applied, as given.")


class EndpointDetail(_Contract):
    """Since 1.2: the endpoint of a finding, for the drill-down."""

    id: uuid.UUID
    url: str
    path: str
    method: str
    status_code: int | None = None
    content_type: str | None = None
    sensitivity_class: SensitivityClass | None = None
    sensitivity_confidence: float | None = None
    sensitivity_reason: list[str] = Field(default_factory=list)
    body_signals: list[BodySignal] = Field(default_factory=list)
    security_headers: dict[str, str] = Field(
        default_factory=dict, description="Security-relevant response headers (redacted).")
    cookies: list[dict[str, Any]] = Field(
        default_factory=list, description="Cookie metadata: name, flags, scope. Never values.")


class ScanResults(_Contract):
    """Body of ``GET /api/results/{id}`` and of the JSON export."""

    contract_version: str = CONTRACT_VERSION
    scan: ScanStatus
    findings: list[Finding] = Field(
        ..., description="Ranked by final_score, highest first (ties: check_id). Empty "
                         "until status is DONE. Filtered/paginated when the request asks.")
    chains: list[Chain] = Field(default_factory=list)
    findings_meta: FindingsMeta | None = Field(
        None, description="Since 1.2. Set when the request filters or paginates: the "
                          "filtered total and the page. Null otherwise and in exports.")

    @model_validator(mode="after")
    def _rank_findings(self) -> ScanResults:
        self.findings.sort(key=lambda f: (-f.final_score, f.check_id, str(f.id)))
        return self


class FindingDetail(Finding):
    """Since 1.2: body of ``GET /api/results/{scan_id}/findings/{finding_id}``."""

    description: str | None = None
    impact: str | None = None
    references: list[str] = Field(default_factory=list)
    endpoint: EndpointDetail | None = Field(None, description="Null for host-level findings.")
    chains: list[Chain] = Field(default_factory=list,
                                description="The chains this finding belongs to.")
