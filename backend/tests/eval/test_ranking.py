"""ranking.py --scoring environmental: legacy-scored findings and the priority items
they would answer are left out, so the experiment tests the CVSS method alone."""

from __future__ import annotations

import json

from tests.eval.conftest import load_eval_script


def test_environmental_only_drops_legacy_findings_and_their_items(tmp_path, monkeypatch):
    ranking = load_eval_script("harness/ranking.py")
    run = tmp_path / "raw" / "cawasma" / "vampi" / "20261104T000000Z"
    run.mkdir(parents=True)
    url = "https://vampi-tls"
    findings = [
        {
            "check_id": "HDR-001",
            "endpoint_url": url + "/",
            "base_score": 5.3,
            "final_score": 7.1,
            "final_vector": "CVSS:3.1/...CR:H",
        },
        {
            "check_id": "INF-003",
            "endpoint_url": url + "/.env",
            "base_score": 9.1,
            "final_score": 10.0,
            "final_vector": None,
        },
    ]
    (run / "results.json").write_text(json.dumps({"findings": findings}))
    monkeypatch.setattr(ranking.ev, "RESULTS", tmp_path)
    monkeypatch.setattr(
        ranking,
        "load_priority",
        lambda t: [
            {"check_id": "HDR-001", "endpoint": "/", "grade": 1},
            {"check_id": "INF-003", "endpoint": "/.env", "grade": 3},
        ],
    )

    every = ranking.experiment("vampi", 13, run_stamp=run.name)
    env = ranking.experiment("vampi", 13, run_stamp=run.name, environmental_only={"HDR-001"})
    assert (every["findings"], every["priority_items"], every["critical_items"]) == (2, 2, 1)
    assert (env["findings"], env["priority_items"], env["critical_items"]) == (1, 1, 0)
    assert env["ndcg10_before"] == env["ndcg10_after"] == 1.0


def test_environmental_check_ids_are_the_spec_registry():
    ranking = load_eval_script("harness/ranking.py")
    ids = ranking.environmental_check_ids()
    assert "HDR-001" in ids and "HDR-009" not in ids  # HDR-009 is a legacy @rule
