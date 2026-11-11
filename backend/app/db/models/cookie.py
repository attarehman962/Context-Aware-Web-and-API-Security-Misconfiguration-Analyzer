"""Cookie model -- metadata for a cookie set by an endpoint.

Only cookie *metadata* is stored (flags, scope), never the secret token value
itself.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Enum, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.db.models.enums import SameSite

if TYPE_CHECKING:
    from app.db.models.endpoint import Endpoint


class Cookie(Base, TimestampMixin):
    __tablename__ = "cookies"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Value is NOT stored; we keep only its length/entropy signal if needed.
    value_length: Mapped[int | None] = mapped_column(nullable=True)

    http_only: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    secure: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    same_site: Mapped[SameSite] = mapped_column(
        Enum(SameSite, name="cookie_samesite"),
        default=SameSite.UNSET,
        nullable=False,
    )
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    path: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    endpoint: Mapped[Endpoint] = relationship(back_populates="cookies")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Cookie {self.name} secure={self.secure} httponly={self.http_only}>"
