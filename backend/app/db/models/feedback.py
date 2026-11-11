"""Feedback model -- analyst correction / false-positive flag.

Belongs to a scan and optionally to one finding: a scan-level note has no
``finding_id``. Lets an analyst mark a finding as a false positive, which can
later feed classifier tuning.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.db.models.finding import Finding
    from app.db.models.scan import Scan


class Feedback(Base, TimestampMixin):
    __tablename__ = "feedback"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="feedback")
    finding: Mapped[Finding | None] = relationship(back_populates="feedback")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Feedback finding={self.finding_id} fp={self.is_false_positive}>"
