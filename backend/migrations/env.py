"""Alembic migration environment (async).

Migrations run on the same async drivers as the app (asyncpg / aiosqlite) via
``AsyncConnection.run_sync``. The database URL comes from, in order:

1. ``sqlalchemy.url`` set on the Alembic config (used by the migration tests),
2. the ``ALEMBIC_SQLALCHEMY_URL`` env var, or
3. ``settings.DATABASE_URL``.

Sync URLs (``postgresql://``, ``postgresql+psycopg2://``, ``sqlite://``) are
converted to their async driver, so older commands keep working.

All models are imported via ``app.db.models`` so ``target_metadata`` sees every
table for autogenerate.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection, make_url
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import settings
from app.db.models import Base  # registers all tables

config = context.config

if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

_ASYNC_DRIVERS = {"postgresql": "postgresql+asyncpg", "sqlite": "sqlite+aiosqlite"}


def _database_url() -> str:
    raw = (
        config.get_main_option("sqlalchemy.url")
        or os.environ.get("ALEMBIC_SQLALCHEMY_URL")
        or settings.DATABASE_URL
    )
    url = make_url(raw)
    backend = url.get_backend_name()
    if url.get_driver_name() not in ("asyncpg", "aiosqlite") and backend in _ASYNC_DRIVERS:
        url = url.set(drivername=_ASYNC_DRIVERS[backend])
    return url.render_as_string(hide_password=False)


def _configure(connection: Connection | None = None, **kwargs: object) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=(connection is not None and connection.dialect.name == "sqlite"),
        **kwargs,  # type: ignore[arg-type]
    )


def run_migrations_offline() -> None:
    """Emit SQL to the script output without a live DB connection."""
    _configure(url=_database_url(), literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def _run_sync(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations against a live DB connection on the async engine."""
    engine = create_async_engine(_database_url(), poolclass=pool.NullPool)
    async with engine.connect() as connection:
        await connection.run_sync(_run_sync)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
