"""SEC review 4: no secret leaves the scanner unredacted.

``logging_target`` (conftest) serves fake secrets: a JWT, AWS keys, passwords in
a .env file and in JSON, an API key in a response header, a session cookie
value, a private key in a script, and a card number. A full active scan runs
through the real runner into the test database with DEBUG logging captured.
Then every table of the database, the captured logs, every export format
and every read route are searched for each
secret value.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import shutil
import subprocess

import pytest
from sqlalchemy import select

import app.services.scan_runner as runner
from app.core.pipeline import run_pipeline
from app.db.models import Base, Scan
from app.db.models.enums import ScanStatus
from tests.security.conftest import SECRETS

pytestmark = pytest.mark.asyncio

# Values that must never appear. The card number is PII, not a credential: it is
# listed separately so a leak there is reported as its own issue.
CREDENTIALS = {k: v for k, v in SECRETS.items() if k != "card"}


@pytest.fixture
async def scanned(logging_target, sessionmaker_, monkeypatch, caplog):
    @contextlib.asynccontextmanager
    async def scope():
        async with sessionmaker_() as s:
            yield s

    monkeypatch.setattr(runner, "session_scope", scope)
    monkeypatch.setattr(runner, "run_pipeline", functools.partial(run_pipeline, allow_private=True))
    async with sessionmaker_() as s:
        scan = Scan(
            target_url=logging_target.url,
            status=ScanStatus.QUEUED,
            progress=0,
            options={"passive_only": False, "use_wordlist": True, "crawl_depth": 2},
        )
        s.add(scan)
        await s.commit()
    caplog.set_level(logging.DEBUG)
    await runner.run_scan_async(scan.id)
    async with sessionmaker_() as s:
        done = await s.get(Scan, scan.id)
        assert done.status == ScanStatus.DONE, done.error_message
    # The scan must actually have seen the secrets, or the test proves nothing.
    seen = {r.path.split("?")[0] for r in logging_target.log}
    assert {"/", "/api/users", "/.env", "/static/app.js"} <= seen, seen
    return scan.id


def _leaks(text: str, values: dict[str, str]) -> list[str]:
    return [name for name, value in values.items() if value in text]


async def _database_text(sessionmaker_) -> dict[str, str]:
    out: dict[str, str] = {}
    async with sessionmaker_() as s:
        for table in Base.metadata.sorted_tables:
            rows = (await s.execute(select(table))).all()
            out[table.name] = "\n".join(repr(tuple(r)) for r in rows)
    return out


async def test_database_holds_no_secret(scanned, sessionmaker_):
    tables = await _database_text(sessionmaker_)
    leaks = {t: _leaks(text, CREDENTIALS) for t, text in tables.items()}
    assert {t: v for t, v in leaks.items() if v} == {}


async def test_database_holds_no_card_number(scanned, sessionmaker_):
    tables = await _database_text(sessionmaker_)
    assert {t for t, text in tables.items() if SECRETS["card"] in text} == set()


async def test_logs_hold_no_secret(scanned, caplog):
    text = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
    assert _leaks(text, SECRETS) == []


@pytest.mark.parametrize("fmt", ["json", "csv", "html", "pdf"])
async def test_contract_exports_hold_no_secret(client, scanned, fmt):
    r = await client.get(f"/api/results/{scanned}/export", params={"format": fmt})
    assert r.status_code == 200, r.text
    text = r.text if fmt != "pdf" else _pdf_text(r.content)
    assert _leaks(text, SECRETS) == []


async def test_read_routes_hold_no_secret(client, scanned, sessionmaker_, monkeypatch):
    from app.api.routes import contract

    monkeypatch.setattr(contract, "AsyncSessionLocal", sessionmaker_)  # SSE's own session
    paths = [f"/api/results/{scanned}?limit=500", f"/api/scan/{scanned}/events", "/api/scans"]
    results = (await client.get(f"/api/results/{scanned}?limit=500")).json()
    paths += [f"/api/results/{scanned}/findings/{f['id']}" for f in results["findings"]]
    leaks = {}
    for path in paths:
        r = await client.get(path)
        assert r.status_code == 200, (path, r.text)
        if found := _leaks(r.text, SECRETS):
            leaks[path.replace(str(scanned), "{id}")] = found
    assert leaks == {}


async def test_cookie_values_are_never_stored(scanned, sessionmaker_):
    """CLAUDE.md: cookies store metadata, never values."""
    tables = await _database_text(sessionmaker_)
    assert all(SECRETS["session_cookie"] not in t for t in tables.values())


def _pdf_text(pdf: bytes) -> str:
    assert pdf[:5] == b"%PDF-"
    tool = shutil.which("pdftotext")
    if tool is None:
        pytest.skip("pdftotext not installed (poppler-utils)")
    done = subprocess.run(  # noqa: S603 - fixed tool, our PDF
        [tool, "-", "-"], input=pdf, capture_output=True, check=True
    )
    return done.stdout.decode()


def test_secret_fixture_values_are_distinct():
    assert len(set(SECRETS.values())) == len(SECRETS)
