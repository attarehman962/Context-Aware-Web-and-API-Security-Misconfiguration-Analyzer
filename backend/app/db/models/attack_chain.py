"""AttackChain model and the chain_findings association table.

A chain (contribution 2) only exists when its required member findings are
actually detected. The composite score is a documented *template* value for a
known pattern, stored as ``template_composite_score`` so it is never mistaken
for a computed CVSS (spec section 6 & Phase-1 conflict resolution).
"""
from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Column,
    Enum,
    Float,
    ForeignKey,
    String,
    Table,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin
from app.db.models.enums import Severity

if TYPE_CHECKING:
    from app.db.models.finding import Finding
    from app.db.models.scan import Scan


# Many-to-many between attack_chains and findings (spec section 21).
chain_findings = Table(
    "chain_findings",
    Base.metadata,
    Column(
        "chain_id",
        ForeignKey("attack_chains.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "finding_id",
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class AttackChain(Base, TimestampMixin):
    __tablename__ = "attack_chains"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Template identity, e.g. "C005".
    chain_code: Mapped[str] = mapped_column(String(8), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # The chain's own score: the CVSS v3.1 base score of the template's
    # composite vector (config/chains.yaml), above every member's (SRS O4).
    template_composite_score: Mapped[float] = mapped_column(Float, nullable=False)
    composite_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Why it fired: scope unit, matched check ids per group, and the context
    # (sensitivity class / body signal) that satisfied the gates.
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="chain_severity"), nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="attack_chains")
    findings: Mapped[list[Finding]] = relationship(
        secondary=chain_findings, back_populates="chains"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AttackChain {self.chain_code} {self.severity}>"
