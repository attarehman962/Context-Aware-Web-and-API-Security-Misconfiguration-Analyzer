"""Finding model -- one security finding produced by a check.

Scoring fields are deliberately split so the official CVSS v3.1 value
(``base_score``) and CAWASMA's context-adjusted value (``final_score``) are
never confused. This distinction is a core honesty
requirement of the project.

``evidence`` is redacted JSON: ``{"text": str, ...}`` where ``text`` is the
human-readable summary and any other keys are check-specific detail.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Enum,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin
from app.db.models.enums import ContextClass, FindingCategory, Severity

if TYPE_CHECKING:
    from app.db.models.attack_chain import AttackChain
    from app.db.models.endpoint import Endpoint
    from app.db.models.feedback import Feedback
    from app.db.models.scan import Scan


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # A finding may be host-wide (e.g. TLS) rather than tied to one endpoint.
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Identity
    # Catalog rule id, e.g. "HDR-003" (backend/app/core/checks/catalog.py).
    check_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[FindingCategory] = mapped_column(
        Enum(FindingCategory, name="finding_category"), nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Standards mappings, e.g. ["API8:2023"] and ["CWE-1021"].
    owasp_map: Mapped[list[str]] = mapped_column(JSONType, default=list, nullable=False)
    cwe_map: Mapped[list[str]] = mapped_column(JSONType, default=list, nullable=False)

    # Context (from endpoint classification)
    context_class: Mapped[ContextClass | None] = mapped_column(
        Enum(ContextClass, name="finding_context_class"), nullable=True
    )
    context_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Official CVSS v3.1 (standard, unmodified)
    cvss_vector: Mapped[str] = mapped_column(String(128), nullable=False)
    base_score: Mapped[float] = mapped_column(Float, nullable=False)

    # CAWASMA custom context-aware score (NOT official CVSS)
    cawasma_context_multiplier: Mapped[float | None] = mapped_column(Float, nullable=True)
    response_bonus: Mapped[float | None] = mapped_column(Float, nullable=True)
    final_score: Mapped[float] = mapped_column(Float, nullable=False)
    # CVSS v3.1 environmental scoring (spec-registry checks, core/cvss.py): the
    # base vector plus CR/IR/AR, from which ``final_score`` recomputes, and why
    # each requirement was set. Null for findings scored by the interim formula.
    final_vector: Mapped[str | None] = mapped_column(String(160), nullable=True)
    score_reasons: Mapped[list[str] | None] = mapped_column(JSONType, nullable=True)

    # Bucket of ``final_score`` (may be forced to CRITICAL on credential exposure).
    severity_bucket: Mapped[Severity] = mapped_column(
        Enum(Severity, name="finding_severity"),
        default=Severity.INFO,
        nullable=False,
        index=True,
    )

    # Evidence / guidance (evidence is stored redacted)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list[str] | None] = mapped_column(JSONType, nullable=True)
    # For checks that can't be confirmed in black-box mode.
    limitation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    scan: Mapped[Scan] = relationship(back_populates="findings")
    endpoint: Mapped[Endpoint | None] = relationship(back_populates="findings")
    feedback: Mapped[list[Feedback]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", passive_deletes=True
    )
    chains: Mapped[list[AttackChain]] = relationship(
        secondary="chain_findings", back_populates="findings"
    )

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity_bucket"),
        Index("ix_findings_scan_final_score", "scan_id", "final_score"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Finding {self.check_id} {self.severity_bucket} final={self.final_score}>"
