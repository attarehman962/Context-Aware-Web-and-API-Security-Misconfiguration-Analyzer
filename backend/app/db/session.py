"""Async database engine and session management.

FastAPI request handlers and the scanner pipeline use an async engine backed by
asyncpg. The :func:`get_session` dependency (or the :data:`SessionDep`
annotation) yields a session per request and guarantees cleanup. Celery workers
and scripts create their own short-lived sessions via :func:`session_scope`
since they run outside the request lifecycle.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import settings


def enable_sqlite_foreign_keys(async_engine: AsyncEngine) -> None:
    """Make SQLite enforce FOREIGN KEY / ON DELETE rules like PostgreSQL does.

    SQLite ignores foreign keys unless ``PRAGMA foreign_keys=ON`` is set on each
    connection, which would silently disable the cascades. No-op on other dialects.
    """
    if async_engine.dialect.name != "sqlite":
        return

    @event.listens_for(async_engine.sync_engine, "connect")
    def _fk_on(dbapi_conn: Any, _record: Any) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


# ``pool_pre_ping`` avoids handing out dead connections after DB restarts.
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
)
enable_sqlite_foreign_keys(engine)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yield a request-scoped async session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


SessionDep = Annotated[AsyncSession, Depends(get_session)]


@asynccontextmanager
async def session_scope() -> AsyncGenerator[AsyncSession, None]:
    """Standalone async session context (used by the scanner / Celery task).

    Commits on success, rolls back on error, always closes.
    """
    session = AsyncSessionLocal()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()
