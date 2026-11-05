"""scripts/coverage_stats.py: the report's coverage line comes from code."""

from __future__ import annotations

import json

from scripts import coverage_stats


def test_counts_add_up_on_the_real_repo(tmp_path):
    s = coverage_stats.stats(raw=tmp_path)  # no eval run kept
    assert s["check_ids"] == s["scored_environmental"] + s["scored_legacy"] + s["not_implemented"]
    assert 0 < s["with_spec"] <= s["check_ids"]
    assert s["findings"] == 0 and "latest eval run" not in coverage_stats.report(s)


def test_ground_truth_ignores_priority_files_and_reads_both_lists(tmp_path):
    (tmp_path / "t.yaml").write_text(
        "known_issues: [{check_id: HDR-001}]\nmust_not_fire: [{check_id: HDR-008}]\n"
    )
    (tmp_path / "priority_t.yaml").write_text("known_issues: [{check_id: TLS-001}]\n")
    assert coverage_stats.ground_truth_ids(tmp_path) == {"HDR-001", "HDR-008"}


def test_findings_are_split_by_scoring_method_from_the_latest_run(tmp_path):
    def run(stamp: str, findings: list[dict]) -> None:
        d = tmp_path / "vampi" / stamp
        d.mkdir(parents=True)
        (d / "results.json").write_text(json.dumps({"findings": findings}))

    run("20261101T000000Z", [{"final_vector": None}])
    run("20261102T000000Z", [{"final_vector": "CVSS:3.1/..."}, {"final_vector": None}])
    s = coverage_stats.stats(raw=tmp_path)
    assert (s["findings"], s["findings_environmental"], s["findings_legacy"]) == (2, 1, 1)
    assert "environmental 1 (50 %), legacy 1 (50 %)" in coverage_stats.report(s)
