"""Re-export of the rule catalog under a stable import path."""

from __future__ import annotations

from app.core.checks.catalog import CATALOG, RuleMeta

__all__ = ["CATALOG", "RuleMeta"]
