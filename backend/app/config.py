"""Central application configuration.

All settings are loaded from environment variables (or a local ``.env`` file)
via ``pydantic-settings``. Nothing in the codebase should read ``os.environ``
directly -- import :data:`settings` from here instead. This keeps configuration
in one place, typed and validated at startup.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed application settings.

    Values are validated once at process start. A missing required value or a
    wrong type raises immediately, so the service fails fast instead of dying
    mid-scan.
    """

    model_config = SettingsConfigDict(
        # Repo-root .env (shared with docker compose), then a local override.
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Environment
    ENVIRONMENT: Literal["development", "staging", "production", "test"] = "development"
    DEBUG: bool = True
    # "json": one JSON object per line (Docker default, for log shippers);
    # "text": human-readable, for local runs.
    LOG_FORMAT: Literal["text", "json"] = "text"

    # Datastores
    # Async driver (asyncpg) everywhere: FastAPI, the scanner pipeline, Celery
    # tasks and Alembic migrations.
    DATABASE_URL: str = "postgresql+asyncpg://cawasma:cawasma@localhost:5432/cawasma"
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # Frontend / CORS
    # Comma-separated list of allowed origins. Never "*": the scanner returns
    # sensitive assessment data, so origins are explicit.
    FRONTEND_ORIGIN: str = "http://localhost:3000"  # Neelam's Next.js app

    # Scanner safety limits
    REQUEST_TIMEOUT: float = 15.0  # seconds per HTTP request
    MAX_RESPONSE_SIZE: int = 5_000_000  # bytes; larger bodies are truncated
    MAX_ENDPOINTS: int = 200  # hard cap on discovered endpoints
    MAX_CRAWL_DEPTH: int = 2  # recursive crawl depth
    MAX_REDIRECTS: int = 5
    MAX_CONCURRENT_REQUESTS: int = 10  # httpx connection concurrency
    MAX_CONCURRENT_ENDPOINTS: int = 8  # endpoints analysed at once (each sends ~4 probes)
    RATE_LIMIT_PROBE_COUNT: int = 15  # burst size for rate-limit check
    USER_AGENT: str = "CAWASMA-Scanner/1.0 (+defensive-security-research)"
    REQUEST_RETRIES: int = 1  # retries for transient network errors (GET/HEAD)
    MAX_CRAWL_PAGES: int = 50  # pages the crawler fetches and parses

    # Hostnames allowed to resolve to PRIVATE ranges (comma-separated). Empty by
    # default; set only in the evaluation environment (docker-compose.eval-scan.yml)
    # so the scanner can reach Asim's targets. Loopback, link-local and cloud
    # metadata stay blocked regardless (app/utils/security.py).
    ALLOWED_INTERNAL_HOSTS: str = ""
    # Extra CA certificate(s) (PEM file) the engine trusts on top of the system
    # store. Empty by default; set only for the demo / eval targets, which use
    # self-signed certificates (docker-compose.demo.yml). Verification stays on.
    SCAN_CA_BUNDLE: str = ""

    # Start scans on creation by queueing them on Celery (cawasma.run_scan).
    # Off in tests (no broker).
    AUTO_DISPATCH_SCANS: bool = True
    # Run scans in the api process instead (FastAPI background task; no Celery or
    # Redis needed). For simple deploys and the in-process end-to-end test.
    RUN_SCANS_INLINE: bool = False
    # A scan's own time budget (seconds); below the Celery soft limit (1500 s) so
    # an over-long scan ends FAILED with a message instead of being killed.
    SCAN_TIMEOUT: float = 1200.0
    # POST /api/scan per client IP: "<n>/<second|minute|hour>"; empty disables.
    SCAN_RATE_LIMIT: str = "5/minute"
    # How often GET /api/scan/{id}/events re-reads the scan (seconds).
    SSE_POLL_SECONDS: float = 1.0
    SSE_MAX_STREAMS_PER_CLIENT: int = 10  # open live-status streams per client IP
    # Contract v1 routes answer with example data (app/api/mock.py): no DB or
    # scanner needed. For frontend development only.
    MOCK_API: bool = False

    # Spec files (checks.yaml, cvss_mapping.yaml, chains.yaml). Defaults to the
    # repo's config/ dir; in Docker that resolves to /config (mounted).
    CONFIG_DIR: str = str(Path(__file__).resolve().parents[2] / "config")

    # Optional LLM (never required for core scanning)
    # Used by the NLP classifier to expand URL abbreviations (usr -> user).
    # When disabled or no key is set, the built-in abbreviation table is used.
    OPENAI_API_KEY: str | None = None
    ANTHROPIC_API_KEY: str | None = None
    LLM_ENABLED: bool = False
    LLM_PROVIDER: Literal["openai", "anthropic"] = "anthropic"
    LLM_MODEL: str = ""  # blank -> provider default

    # Derived helpers
    @property
    def allowed_internal_hosts(self) -> frozenset[str]:
        return frozenset(
            h.strip().rstrip(".").lower()
            for h in self.ALLOWED_INTERNAL_HOSTS.split(",")
            if h.strip()
        )

    @property
    def frontend_origins(self) -> list[str]:
        """CORS origins as a clean list."""
        return [o.strip() for o in self.FRONTEND_ORIGIN.split(",") if o.strip()]

    @field_validator("MAX_CRAWL_DEPTH")
    @classmethod
    def _cap_depth(cls, v: int) -> int:
        # Depth is intentionally shallow for a safe black-box scanner.
        if v > 4:
            raise ValueError("MAX_CRAWL_DEPTH must be <= 4 for safe scanning")
        return v


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance (one per process)."""
    return Settings()


settings = get_settings()
