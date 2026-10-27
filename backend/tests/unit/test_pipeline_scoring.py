"""Pipeline wiring of spec-registry checks to environmental scoring (Atta Prompt 7)."""
from __future__ import annotations

import pytest
from cvss import CVSS3

from app.core import pipeline
from app.core.body_classifier import classify_body
from app.core.checks.registry import load_implementations
from app.core.contracts import BodySignal, SensitivityClass
from app.core.pipeline import ScanError, body_signals, run_pipeline
from tests.checks.helpers import endpoint, response

load_implementations()


def _spec(resp, cls=SensitivityClass.LOW, signals=frozenset()):
    return pipeline._spec_findings(resp, endpoint(resp.final_url),
                                   context_class=cls, confidence=0.9,
                                   signals=set(signals), ep_index=0)


def test_missing_hsts_is_scored_with_a_recomputable_environmental_vector():
    [finding] = [f for f in _spec(response(headers={})) if f.raw.rule_id == "HDR-001"]
    parsed = CVSS3(finding.final_vector)
    assert finding.final_vector.startswith(finding.raw.cvss_vector + "/CR:")
    assert float(parsed.base_score) == finding.cvss_base_score
    assert float(parsed.environmental_score) == finding.cawasma_final_score
    assert finding.context_multiplier is None and finding.response_bonus is None
    assert finding.evidence["text"].startswith("Missing Strict-Transport-Security")
    assert finding.owasp_map and finding.cwe_map
    assert finding.score_reasons[-1] == f"environmental:{finding.cawasma_final_score}"


def test_context_raises_the_score_of_the_same_finding():
    resp = response(headers={})
    low = next(f for f in _spec(resp) if f.raw.rule_id == "HDR-001")
    high = next(f for f in _spec(resp, SensitivityClass.CRITICAL, {BodySignal.CREDENTIALS})
                if f.raw.rule_id == "HDR-001")
    assert high.cvss_base_score == low.cvss_base_score
    assert high.cawasma_final_score > low.cawasma_final_score


def test_no_spec_findings_when_hsts_is_strong():
    resp = response(headers={"Strict-Transport-Security":
                             "max-age=31536000; includeSubDomains; preload"})
    assert not [f for f in _spec(resp) if f.raw.rule_id in {"HDR-001", "TLS-009"}]


def test_body_signals_follow_the_body_classifier():
    body = classify_body("DB_PASSWORD=hunter2\nhost 10.0.3.17", "text/plain")
    assert {BodySignal.CREDENTIALS, BodySignal.INTERNAL_IP} <= body_signals(body)
    assert body_signals(None) == set()


@pytest.mark.asyncio
async def test_unreachable_target_fails_instead_of_completing():
    # Port 9 on loopback (discard) is closed; allow_private lets the request out.
    with pytest.raises(ScanError, match="Target unreachable"):
        await run_pipeline("https://127.0.0.1:9/", probe=False, allow_private=True)
