"""Shared FastAPI dependencies."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Query


@dataclass
class PaginationParams:
    page: int
    limit: int

    @property
    def offset(self) -> int:
        """The SQL offset for this page."""
        return (self.page - 1) * self.limit


def pagination(
    page: int = Query(1, ge=1, description="1-based page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
) -> PaginationParams:
    """Dependency yielding validated pagination parameters."""
    return PaginationParams(page=page, limit=limit)
