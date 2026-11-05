"""Reset the database: drop everything, re-apply all migrations, optionally seed.

Destroys all data in the configured database (``DATABASE_URL``), including the
Alembic version table and PostgreSQL enum types, then runs
``alembic upgrade head``. Refuses to run when ``ENVIRONMENT=production``.

    python scripts/reset.py --yes          # drop + migrate
    python scripts/reset.py --yes --seed   # drop + migrate + sample data (make reset)
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import settings
from app.utils.logging import configure_logging, get_logger

logger = get_logger(__name__)

BACKEND_DIR = Path(__file__).resolve().parent.parent


async def drop_everything(url: str) -> None:
    """Remove every table (and, on PostgreSQL, every type) in the database."""
    engine = create_async_engine(url)
    try:
        async with engine.begin() as conn:
            if conn.dialect.name == "postgresql":
                await conn.execute(text("DROP SCHEMA public CASCADE"))
                await conn.execute(text("CREATE SCHEMA public"))
            else:
                # Reflect so tables unknown to the current models go too.
                meta = MetaData()
                await conn.run_sync(meta.reflect)
                await conn.run_sync(meta.drop_all)
    finally:
        await engine.dispose()


def alembic_config(url: str | None = None) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    # Keep this process's logging config; alembic.ini would disable our loggers.
    cfg.attributes["configure_logger"] = False
    if url:
        cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--yes", action="store_true", help="confirm data loss")
    parser.add_argument("--seed", action="store_true", help="load sample data afterwards")
    args = parser.parse_args(argv)

    configure_logging()
    if settings.ENVIRONMENT == "production":
        logger.error("reset: refusing to run with ENVIRONMENT=production")
        return 2
    if not args.yes:
        logger.error("reset: this deletes ALL data; re-run with --yes")
        return 1

    url = settings.DATABASE_URL
    asyncio.run(drop_everything(url))
    logger.info("reset: database emptied")
    command.upgrade(alembic_config(url), "head")
    logger.info("reset: migrations applied")
    if args.seed:
        try:
            from scripts.seed import seed
        except ImportError:  # run as a file: scripts/ itself is on sys.path
            from seed import seed  # type: ignore[import-not-found,no-redef]

        asyncio.run(seed())
    return 0


if __name__ == "__main__":
    sys.exit(main())
