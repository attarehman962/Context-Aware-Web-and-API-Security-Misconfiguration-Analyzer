"""Health check response schema."""

from __future__ import annotations

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(..., examples=["ok"])
    service: str = Field(..., examples=["cawasma-backend"])
    version: str = Field(..., examples=["1.0.0"])
    environment: str = Field(..., examples=["development"])
    dependencies: dict[str, str] = Field(
        default_factory=dict,
        description="Liveness of external dependencies (db, redis).",
        examples=[{"database": "ok", "redis": "ok"}],
    )
