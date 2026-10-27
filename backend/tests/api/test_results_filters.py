"""Contract 1.2: results filters, pagination and the finding detail route."""
from __future__ import annotations

import uuid

import pytest

from app.api import mock
from app.api.schemas import ScanResults
from app.api.schemas.contract import FindingDetail
from app.config import settings
from tests.api.test_contract_routes import mock_mode, seeded  # noqa: F401 - fixtures

pytestmark = pytest.mark.asyncio


async def _results(client, scan_id, **params) -> ScanResults:
    r = await client.get(f"/api/results/{scan_id}", params=params)
    assert r.status_code == 200, r.text
    return ScanResults.model_validate(r.json())


async def test_unfiltered_results_are_unchanged(client, seeded):  # noqa: F811
    results = await _results(client, seeded)
    assert results.findings_meta is None and len(results.findings) == 10   # the rescan


async def test_filters_combine_and_keep_whole_scan_counts(client, seeded):  # noqa: F811
    everything = await _results(client, seeded)
    high = await _results(client, seeded, severity=["CRITICAL", "HIGH"])
    assert {f.severity_bucket.value for f in high.findings} <= {"CRITICAL", "HIGH"}
    assert high.findings_meta.total == len(high.findings)
    assert high.findings_meta.filters == {"severity": ["CRITICAL", "HIGH"]}
    assert high.scan.severity_counts == everything.scan.severity_counts      # whole scan
    assert high.chains == everything.chains

    headers = await _results(client, seeded, category="HEADERS")
    assert headers.findings and {f.category.value for f in headers.findings} == {"HEADERS"}

    both = await _results(client, seeded, category="HEADERS", severity="CRITICAL")
    assert all(f.category.value == "HEADERS" and f.severity_bucket.value == "CRITICAL"
               for f in both.findings)


async def test_in_chain_and_owasp_filters(client, seeded):  # noqa: F811
    members = await _results(client, seeded, in_chain="true")
    assert members.findings and all(f.chain_ids for f in members.findings)
    others = await _results(client, seeded, in_chain="false")
    assert all(not f.chain_ids for f in others.findings)
    total = len((await _results(client, seeded)).findings)
    assert members.findings_meta.total + others.findings_meta.total == total

    owasp = members.findings[0].owasp_map[0]
    by_owasp = await _results(client, seeded, owasp=owasp.lower())    # case-insensitive
    assert by_owasp.findings and all(owasp in f.owasp_map for f in by_owasp.findings)


async def test_pagination_keeps_the_ranking(client, seeded):  # noqa: F811
    everything = (await _results(client, seeded)).findings
    first = await _results(client, seeded, page=1, limit=5)
    second = await _results(client, seeded, page=2, limit=5)
    assert first.findings_meta.model_dump() == {
        "total": len(everything), "page": 1, "limit": 5,
        "pages": (len(everything) + 4) // 5, "filters": {}}
    assert [f.id for f in first.findings + second.findings] == [f.id for f in everything[:10]]


@pytest.mark.parametrize("params", [{"severity": "SEVERE"}, {"category": "NOPE"},
                                    {"page": 0}, {"limit": 501}])
async def test_bad_filter_values_are_422(client, seeded, params):  # noqa: F811
    r = await client.get(f"/api/results/{seeded}", params=params)
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR"


async def test_finding_detail(client, seeded):  # noqa: F811
    results = await _results(client, seeded)
    env = next(f for f in results.findings if f.check_id == "INF-003")
    r = await client.get(f"/api/results/{seeded}/findings/{env.id}")
    assert r.status_code == 200, r.text
    detail = FindingDetail.model_validate(r.json())
    assert detail.id == env.id and detail.endpoint and detail.endpoint.path == "/.env"
    assert {s.value for s in detail.endpoint.body_signals} >= {"CREDENTIALS"}
    assert [c.chain_code for c in detail.chains] == ["C005"]
    assert detail.chains[0].composite_vector and detail.chains[0].evidence["groups"]

    host_level = next(f for f in results.findings if f.endpoint_id is None)
    r = await client.get(f"/api/results/{seeded}/findings/{host_level.id}")
    assert r.status_code == 200 and r.json()["endpoint"] is None


async def test_finding_detail_404s(client, seeded):  # noqa: F811
    for path in (f"/api/results/{seeded}/findings/{uuid.uuid4()}",
                 f"/api/results/{uuid.uuid4()}/findings/{uuid.uuid4()}"):
        r = await client.get(path)
        assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"


# ------------------------------------------------------------- mock mode

async def test_mock_mode_filters_and_detail_match_the_real_shapes(client, mock_mode):  # noqa: F811
    assert settings.MOCK_API
    crit = await _results(client, mock.DONE_ID, severity="CRITICAL", page=1, limit=2)
    assert crit.findings_meta.total >= len(crit.findings) and len(crit.findings) <= 2
    r = await client.get(f"/api/results/{mock.DONE_ID}/findings/{mock.CHAIN_MEMBER_ID}")
    detail = FindingDetail.model_validate(r.json())
    assert detail.check_id == "INF-003" and [c.chain_code for c in detail.chains] == ["C005"]
    assert detail.evidence["chains"][0]["chain_id"] == "C005"
