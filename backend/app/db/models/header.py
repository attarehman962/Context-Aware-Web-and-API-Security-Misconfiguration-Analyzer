"""Header model -- a security-relevant HTTP response header for an endpoint.

Values are stored already redacted where sensitive (e.g. Authorization). Only
headers relevant to the checks are persisted, not every header.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.db.models.endpoint import Endpoint


class Header(Base, TimestampMixin):
    __tablename__ = "headers"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)  # redacted if sensitive

    endpoint: Mapped[Endpoint] = relationship(back_populates="headers")

    def __repr__(self) -> str:  # pragma: no cover
        """Readable debug representation."""
        return f"<Header {self.name}>"
