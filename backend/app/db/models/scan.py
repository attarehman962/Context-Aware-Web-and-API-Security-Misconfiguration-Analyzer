"""Scan model -- the top-level record for one scan job.

Everything else (endpoints, findings, chains, TLS info, AI insights, feedback)
hangs off a scan and is deleted with it via ON DELETE CASCADE. A scan also
records the options it ran with and the operator's confirmation that they are
authorised to test the target.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin
from app.db.models.enums import ScanStatus

if TYPE_CHECKING:
    from app.db.models.ai_insight import AiInsight
    from app.db.models.attack_chain import AttackChain
    from app.db.models.endpoint import Endpoint
    from app.db.models.feedback import Feedback
    from app.db.models.finding import Finding
    from app.db.models.tls import TlsInfo


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"),
        default=ScanStatus.QUEUED,
        nullable=False,
        index=True,
    )
    # Progress 0-100 and a human-readable current stage.
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_stage: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Per-stage counts the worker updates as it goes, e.g. {"stage": "checking",
    # "endpoints_found": 42, "endpoints_checked": 17, "findings": 31}.
    progress_detail: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    # Set by POST /api/scan/{id}/cancel; the worker stops at its next progress step.
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Effective scan settings (limits, probes) so a result can be reproduced.
    options: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    # Operator confirmed they are authorised to test the target, and when.
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Timezone-aware: the scan runner writes datetime.now(UTC).
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships (all cascade-delete with the scan)
    endpoints: Mapped[list[Endpoint]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    attack_chains: Mapped[list[AttackChain]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    tls_info: Mapped[list[TlsInfo]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    ai_insights: Mapped[list[AiInsight]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )
    feedback: Mapped[list[Feedback]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        Index("ix_scans_status_created", "status", "created_at"),
        Index("ix_scans_target_created", "target_url", "created_at"),
        # The flag and its timestamp are set together or not at all.
        CheckConstraint(
            "(authorization_confirmed AND authorization_confirmed_at IS NOT NULL)"
            " OR (NOT authorization_confirmed AND authorization_confirmed_at IS NULL)",
            name="ck_scans_authorization_timestamp",
        ),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Scan {self.id} {self.status} {self.target_url!r}>"
