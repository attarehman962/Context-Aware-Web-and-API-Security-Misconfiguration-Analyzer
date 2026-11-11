"""AiInsight model -- optional LLM-generated executive summary for a scan.

Optional by design: the core scanner works with no LLM key.
Sensitive data is redacted before ever being sent to an external model.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.db.models.scan import Scan


class AiInsight(Base, TimestampMixin):
    __tablename__ = "ai_insights"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)  # openai|anthropic
    summary: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="ai_insights")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AiInsight {self.provider} scan={self.scan_id}>"
