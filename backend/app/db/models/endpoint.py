"""Endpoint model -- one discovered URL/method within a scan.

Stores the NLP sensitivity classification (contribution 1) and the
response-body signals (contribution 3) alongside basic response metadata. Both
feed the context-aware score of the endpoint's findings.

``body_signals`` shape (see docs/schema.md)::

    {"credentials": bool, "pii": bool, "financial": bool, "internal_ip": bool,
     "bonus": float, "reasons": [str, ...]}
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin
from app.db.models.enums import ContextClass, DiscoveryMethod

if TYPE_CHECKING:
    from app.db.models.cookie import Cookie
    from app.db.models.finding import Finding
    from app.db.models.header import Header
    from app.db.models.scan import Scan


class Endpoint(Base, TimestampMixin):
    __tablename__ = "endpoints"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # NLP sensitivity classification (contribution 1)
    # ``context_class`` is the endpoint-sensitivity class (CRITICAL..LOW).
    context_class: Mapped[ContextClass | None] = mapped_column(
        Enum(ContextClass, name="context_class"), nullable=True
    )
    context_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Explainable reasons, e.g. ["Contains authentication-related tokens"].
    context_reason: Mapped[list[str] | None] = mapped_column(JSONType, nullable=True)

    # Response-body signals (contribution 3), redacted
    body_signals: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    response_time: Mapped[float | None] = mapped_column(Float, nullable=True)
    discovered_by: Mapped[DiscoveryMethod] = mapped_column(
        Enum(DiscoveryMethod, name="discovery_method"),
        default=DiscoveryMethod.SEED,
        nullable=False,
    )

    # Relationships
    scan: Mapped[Scan] = relationship(back_populates="endpoints")
    findings: Mapped[list[Finding]] = relationship(back_populates="endpoint", passive_deletes=True)
    headers: Mapped[list[Header]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan", passive_deletes=True
    )
    cookies: Mapped[list[Cookie]] = relationship(
        back_populates="endpoint", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        # The same URL+method is discovered once per scan (dedup, spec 18).
        UniqueConstraint("scan_id", "url", "method", name="uq_endpoint_scan_url_method"),
        Index("ix_endpoints_scan_context", "scan_id", "context_class"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Endpoint {self.method} {self.path} ctx={self.context_class}>"
