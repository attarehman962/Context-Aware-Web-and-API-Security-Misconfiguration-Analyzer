"""Alembic migrations apply cleanly on an empty database and match the models.

Runs against SQLite by default and against PostgreSQL when ``TEST_DATABASE_URL``
is set (as in CI). Tests are sync because Alembic's async env calls
``asyncio.run`` itself.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from app.db.models import Base
from scripts.reset import alembic_config, drop_everything

ALL_TABLES = set(Base.metadata.tables)


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    return os.environ.get("TEST_DATABASE_URL") or f"sqlite+aiosqlite:///{tmp_path / 'mig.db'}"


@pytest.fixture
def cfg(db_url: str):
    asyncio.run(drop_everything(db_url))
    config: Config = alembic_config(db_url)
    config.attributes["configure_logger"] = False  # keep pytest's logging intact
    yield config
    asyncio.run(drop_everything(db_url))


def _inspect(url: str, fn):
    async def run():
        engine = create_async_engine(url)
        try:
            async with engine.connect() as conn:
                return await conn.run_sync(fn)
        finally:
            await engine.dispose()

    return asyncio.run(run())


def _tables(conn: Connection) -> set[str]:
    return set(inspect(conn).get_table_names())


def _enum_types(conn: Connection) -> int:
    if conn.dialect.name != "postgresql":
        return 0
    return conn.execute(text("SELECT count(*) FROM pg_type WHERE typtype = 'e'")).scalar_one()


def test_upgrade_on_empty_database_creates_every_table(cfg, db_url):
    assert _inspect(db_url, _tables) == set()

    command.upgrade(cfg, "head")

    assert _inspect(db_url, _tables) == ALL_TABLES | {"alembic_version"}
    head = ScriptDirectory.from_config(cfg).get_current_head()
    current = _inspect(db_url, lambda c: MigrationContext.configure(c).get_current_revision())
    assert current == head


def test_migrated_schema_matches_models(cfg, db_url):
    command.upgrade(cfg, "head")

    diff = _inspect(
        db_url,
        lambda c: compare_metadata(
            MigrationContext.configure(c, opts={"compare_type": True}), Base.metadata
        ),
    )
    assert diff == [], f"models and migrations differ; run alembic revision --autogenerate: {diff}"


def test_downgrade_to_base_and_upgrade_again(cfg, db_url):
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")

    assert _inspect(db_url, _tables) <= {"alembic_version"}
    assert _inspect(db_url, _enum_types) == 0  # PostgreSQL enum types dropped too

    command.upgrade(cfg, "head")
    assert _inspect(db_url, _tables) == ALL_TABLES | {"alembic_version"}
