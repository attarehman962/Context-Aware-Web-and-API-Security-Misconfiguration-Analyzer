"""TlsInfo model -- TLS/certificate facts gathered for a scan's host.

TLS is a host-level property, so it links to the scan rather than a single
endpoint. Protocol/cipher probing is implemented in core/tls.py.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONType, TimestampMixin

if TYPE_CHECKING:
    from app.db.models.scan import Scan


class TlsInfo(Base, TimestampMixin):
    __tablename__ = "tls_info"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False)

    # Protocols that the server was observed to *offer*, e.g. ["TLSv1.2","TLSv1.3"].
    protocols_offered: Mapped[list[str] | None] = mapped_column(JSONType, nullable=True)
    # Data model fields: weak cipher suites seen, and the TLS check ids that fired.
    weak_ciphers: Mapped[list[str]] = mapped_column(JSONType, default=list, nullable=False)
    issues: Mapped[list[str]] = mapped_column(JSONType, default=list, nullable=False)
    negotiated_protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    negotiated_cipher: Mapped[str | None] = mapped_column(String(128), nullable=True)

    cert_subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    cert_issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    cert_not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_self_signed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    hostname_matches: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="tls_info")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<TlsInfo {self.host} {self.negotiated_protocol}>"
