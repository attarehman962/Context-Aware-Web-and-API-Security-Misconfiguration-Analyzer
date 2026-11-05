"""Shared API schemas: consistent success/error envelopes and pagination.

Every endpoint returns Pydantic models, never raw ORM objects. The error
envelope matches the format mandated by the project spec (section 44).
"""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ErrorDetail(BaseModel):
    code: str = Field(..., examples=["INVALID_TARGET"])
    message: str = Field(..., examples=["The provided target URL is invalid."])


class ErrorResponse(BaseModel):
    """Standard error body. ``success`` is always ``False``."""

    success: bool = False
    error: ErrorDetail


class PaginationMeta(BaseModel):
    page: int = Field(..., ge=1, examples=[1])
    limit: int = Field(..., ge=1, examples=[20])
    total: int = Field(..., ge=0, examples=[100])
    pages: int = Field(..., ge=0, examples=[5])


class Page(BaseModel, Generic[T]):
    """Generic paginated collection wrapper."""

    items: list[T]
    meta: PaginationMeta
