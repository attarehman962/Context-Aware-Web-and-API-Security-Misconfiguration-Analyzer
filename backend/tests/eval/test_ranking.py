"""ranking.py --scoring environmental: legacy-scored findings and the priority items
they would answer are left out, so the experiment tests the CVSS method alone."""

from __future__ import annotations

import json

import pytest

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


def _raw_run(tmp_path, findings):
    run = tmp_path / "raw" / "cawasma" / "vampi" / "20261104T000000Z"
    run.mkdir(parents=True)
    (run / "results.json").write_text(json.dumps({"findings": findings}))
    return run


def _f(cid, path, base, final, vector="CVSS:3.1/x"):
    return {
        "check_id": cid,
        "endpoint_url": "https://vampi-tls" + path,
        "base_score": base,
        "final_score": final,
        "final_vector": vector,
        "evidence": {"text": f"{cid} {path}"},
    }


def test_pool_is_the_blind_union_of_both_top_k(tmp_path, monkeypatch):
    pool = load_eval_script("harness/pool.py")
    monkeypatch.setattr(pool.ev, "RESULTS", tmp_path)
    _raw_run(
        tmp_path,
        [
            _f("HDR-002", "/", 5.4, 5.4),
            _f("HDR-002", "/", 5.4, 5.4),  # same pair twice
            _f("HDR-002", "/admin", 5.4, 7.0),
            _f("HDR-001", "/", 5.9, 5.9),
            _f("HDR-009", "/", 9.9, 9.9, vector=None),  # legacy: left out
        ],
    )
    rows = pool.build_pool("vampi", "20261104T000000Z", k=1)
    pairs = {(r["check_id"], r["endpoint"]) for r in rows}
    assert pairs == {("HDR-001", "/"), ("HDR-002", "/admin")}  # top-1 of each
    assert all(set(r) == set(pool.COLUMNS) and r["grade"] == "" for r in rows)
    assert all("5.9" not in r["evidence_summary"] for r in rows)  # no scores


def test_graded_pool_drives_ndcg_and_ungraded_falls_back(tmp_path, monkeypatch):
    ranking = load_eval_script("harness/ranking.py")
    monkeypatch.setattr(ranking.ev, "RESULTS", tmp_path)
    monkeypatch.setattr(ranking.ev, "GROUND_TRUTH", tmp_path)
    monkeypatch.setattr(
        ranking, "load_priority", lambda t: [{"check_id": "HDR-002", "endpoint": "/", "grade": 1}]
    )
    run = _raw_run(tmp_path, [_f("HDR-002", "/", 5.4, 5.4), _f("HDR-002", "/admin", 5.4, 7.0)])
    csv_path = tmp_path / "priority_pool_vampi.csv"
    monkeypatch.setattr(ranking, "load_pool", lambda t: _read(csv_path))

    csv_path.write_text(
        "target,check_id,endpoint,evidence_summary,grade\n"
        "vampi,HDR-002,/,x,\nvampi,HDR-002,/admin,x,\n"
    )
    out = ranking.experiment("vampi", 13, run_stamp=run.name, environmental_only={"HDR-002"})
    assert out["pool"] == "ungraded (0/2)" and out["ndcg10_pool_after"] is None
    assert out["items_matched"] == 1

    csv_path.write_text(
        "target,check_id,endpoint,evidence_summary,grade\n"
        "vampi,HDR-002,/,x,1\nvampi,HDR-002,/admin,x,2\n"
    )
    out = ranking.experiment("vampi", 13, run_stamp=run.name, environmental_only={"HDR-002"})
    assert out["pool"] == "graded"
    assert out["ndcg10_pool_after"] == 1.0 > out["ndcg10_pool_before"]  # /admin (2) first


def _read(path):
    import csv

    with path.open() as fh:
        return {
            (r["check_id"], r["endpoint"]): (int(r["grade"]) if r["grade"] else None)
            for r in csv.DictReader(fh)
        }


def test_pool_grades_must_be_0_to_3(tmp_path, monkeypatch):
    pool = load_eval_script("harness/pool.py")
    monkeypatch.setattr(pool, "POOL", tmp_path / "priority_pool_{target}.csv")
    (tmp_path / "priority_pool_vampi.csv").write_text(
        "target,check_id,endpoint,evidence_summary,grade\nvampi,HDR-002,/,x,5\n"
    )
    with pytest.raises(ValueError, match="0-3"):
        pool.load_pool("vampi")


def test_refresh_keeps_entered_grades_adds_new_pairs_and_drops_ungraded(tmp_path, monkeypatch):
    pool = load_eval_script("harness/pool.py")
    monkeypatch.setattr(pool.ev, "RESULTS", tmp_path)
    monkeypatch.setattr(pool, "POOL", tmp_path / "priority_pool_{target}.csv")
    (tmp_path / "priority_pool_vampi.csv").write_text(
        "target,check_id,endpoint,evidence_summary,grade\n"
        "vampi,HDR-002,/,old,1\n"  # still pooled: grade kept
        "vampi,HDR-005,/old,old,3\n"  # no longer pooled but graded: kept
        "vampi,HDR-006,/gone,old,\n"  # no longer pooled, ungraded: removed
    )
    _raw_run(tmp_path, [_f("HDR-002", "/", 5.4, 5.4), _f("HDR-001", "/new", 5.9, 7.1)])
    rows, st = pool.refresh_pool("vampi", "20261104T000000Z", k=5)
    by_key = {(r["check_id"], r["endpoint"]): r["grade"] for r in rows}
    assert by_key == {("HDR-002", "/"): "1", ("HDR-005", "/old"): "3", ("HDR-001", "/new"): ""}
    assert (st["kept"], st["added"], st["removed"], st["grades_kept"]) == (1, 1, 1, 2)


def test_grouped_view_keeps_one_finding_per_check(tmp_path, monkeypatch):
    ranking = load_eval_script("harness/ranking.py")
    monkeypatch.setattr(ranking.ev, "RESULTS", tmp_path)
    monkeypatch.setattr(
        ranking,
        "load_priority",
        lambda t: [
            {"check_id": "HDR-002", "endpoint": "/", "grade": 1},
            {"check_id": "INF-003", "endpoint": "/.env", "grade": 3},
        ],
    )
    findings = [_f("HDR-002", f"/p{i}", 5.4, 6.0 + i / 10) for i in range(5)]
    findings += [_f("INF-003", "/.env", 9.1, 9.8), _f("HDR-009", "/", 3.1, 3.1, vector=None)]
    run = _raw_run(tmp_path, findings)
    out = ranking.grouped_experiment(
        "vampi", 13, run_stamp=run.name, environmental_only={"HDR-002", "INF-003"}
    )
    assert (out["findings"], out["distinct_checks"], out["groups"]) == (6, 2, 2)
    assert out["top5"][0] == "HDR-002 (5)"
    assert out["ndcg10_before"] == out["ndcg10_after"] == 1.0  # INF-003 first either way
