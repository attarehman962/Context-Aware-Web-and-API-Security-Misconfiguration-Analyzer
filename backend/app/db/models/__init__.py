"""ORM model registry.

Importing this package imports every model, which registers all tables on
``Base.metadata``. Alembic imports this so autogenerate sees the full schema.
"""

from __future__ import annotations

from app.db.base import Base
from app.db.models.ai_insight import AiInsight
from app.db.models.attack_chain import AttackChain, chain_findings
from app.db.models.cookie import Cookie
from app.db.models.endpoint import Endpoint
from app.db.models.enums import (
    ContextClass,
    DiscoveryMethod,
    FindingCategory,
    SameSite,
    ScanStatus,
    Severity,
)
from app.db.models.feedback import Feedback
from app.db.models.finding import Finding
from app.db.models.header import Header
from app.db.models.scan import Scan
from app.db.models.tls import TlsInfo

__all__ = [
    "Base",
    "Scan",
    "Endpoint",
    "Finding",
    "Header",
    "Cookie",
    "TlsInfo",
    "AttackChain",
    "chain_findings",
    "AiInsight",
    "Feedback",
    "ScanStatus",
    "Severity",
    "ContextClass",
    "DiscoveryMethod",
    "FindingCategory",
    "SameSite",
]
