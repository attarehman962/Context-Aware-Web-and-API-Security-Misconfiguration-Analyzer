"""SEC review 2 and 5: passive-only mode and scope, as the target sees them.

A whole scan runs against ``logging_target`` (conftest), which records every
request that arrives. The target links, redirects, frames, scripts and forms
towards ``other.test``; all of those arrive at the same server, with
``Host: other.test``. ``allow_private`` is only so the scanner may reach this
loopback server; passive mode and scope don't depend on it.
"""
from __future__ import annotations

import pytest

from app.core.pipeline import run_pipeline
from app.core.wordlist import PROBE_PATHS

pytestmark = pytest.mark.asyncio

ACTIVE_HEADERS = {"origin", "access-control-request-method"}
# Paths the target itself links to (some are also wordlist entries, e.g. /api/users).
LINKED = {"/", "/about", "/redirect-out", "/redirect-in", "/static/app.js",
          "/api/users", "/api/orders", "/login"}


def _unlinked_probes(target) -> set[str]:
    return ({r.path.split("?")[0] for r in target.log} - LINKED) & set(PROBE_PATHS)


async def _scan(target, **kw):
    return await run_pipeline(target.url, allow_private=True, crawl_depth=2, **kw)


# ---------------------------------------------------------------- passive

async def test_passive_scan_sends_only_get_and_head(logging_target):
    await _scan(logging_target, passive_only=True, probe=False)
    assert logging_target.log, "the scan made no requests"
    assert logging_target.methods() <= {"GET", "HEAD"}


async def test_passive_scan_does_not_probe_the_wordlist(logging_target):
    await _scan(logging_target, passive_only=True, probe=False, use_wordlist=True)
    assert not _unlinked_probes(logging_target), sorted(_unlinked_probes(logging_target))
    assert all("cawasma-" not in r.path for r in logging_target.log)   # soft-404 probe


async def test_passive_scan_sends_no_payloads_or_cors_probes(logging_target):
    await _scan(logging_target, passive_only=True, probe=False)
    for r in logging_target.log:
        assert "cawasma_probe" not in r.path, r.path              # injection probe
        assert not ACTIVE_HEADERS & set(r.headers), (r.path, r.headers)


async def test_passive_scan_through_the_runner_is_passive(logging_target, sessionmaker_,
                                                          monkeypatch):
    """The API path: options.passive_only set by POST /api/scan reaches the engine."""
    import contextlib
    import functools

    import app.services.scan_runner as runner
    from app.db.models import Scan
    from app.db.models.enums import ScanStatus

    @contextlib.asynccontextmanager
    async def scope():
        async with sessionmaker_() as s:
            yield s

    async def quiet(self, *a, **k):
        return None

    monkeypatch.setattr(runner, "session_scope", scope)
    monkeypatch.setattr(runner, "run_pipeline", functools.partial(run_pipeline,
                                                                  allow_private=True))
    monkeypatch.setattr(runner.RedisProgressPublisher, "publish", quiet)
    monkeypatch.setattr(runner.RedisProgressPublisher, "close", quiet)
    async with sessionmaker_() as s:
        scan = Scan(target_url=logging_target.url, status=ScanStatus.QUEUED, progress=0,
                    options={"passive_only": True, "use_wordlist": True, "crawl_depth": 2})
        s.add(scan)
        await s.commit()
    await runner.run_scan_async(scan.id)
    async with sessionmaker_() as s:
        assert (await s.get(Scan, scan.id)).status == ScanStatus.DONE
    assert logging_target.methods() <= {"GET", "HEAD"}
    assert not _unlinked_probes(logging_target)


# ------------------------------------------------------------------ scope

@pytest.mark.parametrize("passive", [True, False])
async def test_no_request_ever_leaves_the_target_host(logging_target, passive):
    await _scan(logging_target, passive_only=passive, probe=not passive)
    off = [(r.method, r.host, r.path) for r in logging_target.log
           if not r.host.lower().startswith("target.test")]
    assert off == [], off


async def test_out_of_scope_links_are_not_reported_as_endpoints(logging_target):
    result = await _scan(logging_target, probe=True)
    assert result.endpoints
    assert all("other.test" not in e.url for e in result.endpoints)


async def test_active_scan_stays_on_the_target_even_with_every_probe(logging_target):
    await _scan(logging_target, probe=True, use_wordlist=True)
    assert logging_target.methods() - {"GET", "HEAD"}, "expected active probes"
    assert logging_target.hosts() == {"target.test"}
