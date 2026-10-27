"""eval/harness/evaluate.py: endpoint rule, normalisers, matching, metrics (Asim Prompt 8)."""
from __future__ import annotations

import json

import pytest
import yaml

from app.core.checks.catalog import CATALOG
from tests.eval.conftest import EVAL_DIR, load_eval_script

ev = load_eval_script("harness/evaluate.py")


@pytest.mark.parametrize("raw, path", [
    ("https://juice-shop-tls/api/Users/42?x=1#f", "/api/Users/:id"),
    ("http://vampi:5000/users/v1/name1/email", "/users/v1/name1/email"),
    ("/books/v1/{book_title}", "/books/v1/:id"),
    ("http://dvwa/config/", "/config"),
    ("http://dvwa", "/"),
    ("/a%20b/5f8d0d55b54764421b7156c3", "/a b/:id"),
    ("/x/123e4567-e89b-12d3-a456-426614174000", "/x/:id"),
    (None, "*"),
])
def test_endpoint_rule(raw, path):
    assert ev.normalise_endpoint(raw) == path


def test_mapping_uses_only_known_check_ids():
    known = set(CATALOG) | {c["check_id"] for c in yaml.safe_load(
        (EVAL_DIR.parent / "config" / "checks.yaml").read_text())["checks"]}
    mapping = ev.load_mapping()
    for tool, rules in mapping.items():
        assert rules, tool
        assert {c for c in rules.values() if c} <= known, tool


def test_zap_alerts_become_one_finding_per_instance():
    mapping = ev.load_mapping()["zap"]
    raw = {"site": [{"alerts": [
        {"pluginid": "10038", "alert": "CSP Header Not Set",
         "instances": [{"uri": "http://dvwa/login.php"}, {"uri": "http://dvwa/setup.php"}]},
        {"pluginid": "10096", "alert": "Timestamp Disclosure", "instances": [{"uri": "http://dvwa/"}]},
        {"pluginid": "99999", "alert": "Something new", "instances": [{"uri": "http://dvwa/"}]},
    ]}]}
    found = ev.normalise_zap("dvwa", raw, mapping)
    assert [(f.check_id, f.endpoint) for f in found] == [
        ("HDR-002", "/login.php"), ("HDR-002", "/setup.php"), (None, "/"), (None, "/")]


def test_nuclei_matcher_then_template_then_path_glob():
    mapping = ev.load_mapping()["nuclei"]
    lines = [json.dumps(r) for r in (
        {"template-id": "http-missing-security-headers", "matcher-name": "x-frame-options",
         "matched-at": "http://vampi:5000/"},
        {"template-id": "git-config", "matched-at": "http://dvwa/.git/config"},
        {"template-id": "zip-backup-files", "template-path":
         "/templates/http/exposures/backups/zip-backup-files.yaml",
         "matched-at": "http://dvwa/backup.zip"},
        {"template-id": "tech-detect", "matcher-name": "nginx", "matched-at": "http://dvwa/"},
    )]
    found = ev.normalise_nuclei("dvwa", lines, mapping)
    assert [(f.check_id, f.endpoint) for f in found] == [
        ("HDR-003", "/"), ("INF-004", "/.git/config"), ("INF-005", "/backup.zip"), (None, "/")]


GT = {"known_issues": [
    {"endpoint": "/login.php", "check_id": "HDR-002", "expected": "present"},
    {"endpoint": "/", "check_id": "HDR-007", "expected": "present"},
    {"endpoint": "/.git/HEAD", "check_id": "INF-004", "expected": "absent"},
    {"endpoint": "/login.php", "check_id": "API-001", "expected": "present"},
], "must_not_fire": [{"check_id": "COR-003", "reason": "x"},
                     {"check_id": "HDR-008", "reason": "x"}]}


def _f(check, endpoint, tool="cawasma"):
    return ev.Finding(tool, "dvwa", check, endpoint, check or "rule-x")


def test_score_counts_every_outcome():
    findings = [_f("HDR-002", "/login.php"),          # TP
                _f("INF-004", "/.git/HEAD"),           # FP (absent entry)
                _f("COR-003", "/api"),                 # FP (must_not_fire)
                _f("HDR-002", "/other"),               # unlabelled
                _f(None, "/")]                         # out of scope
    r = ev.score("cawasma", "dvwa", findings, GT, covered=None)
    assert r.tp == [("HDR-002", "/login.php")]
    assert sorted(r.fn) == [("API-001", "/login.php"), ("HDR-007", "/")]
    assert sorted(r.fp) == [("COR-003", "/api"), ("INF-004", "/.git/HEAD")]
    assert r.tn == [("HDR-008", "*")]
    assert r.unlabelled == [("HDR-002", "/other")] and len(r.out_of_scope) == 1
    m = r.metrics()
    assert (m["precision"], m["recall"], m["fpr"]) == (0.333, 0.333, 0.667)


def test_host_level_findings_match_the_root():
    r = ev.score("cawasma", "dvwa", [_f("HDR-007", "*")], GT, covered=None)
    assert ("HDR-007", "/") in r.tp


def test_tools_are_scored_only_on_what_they_cover():
    r = ev.score("zap", "dvwa", [_f("HDR-002", "/login.php", "zap")], GT,
                 covered={"HDR-002", "HDR-007"})
    assert r.tp == [("HDR-002", "/login.php")] and r.fn == [("HDR-007", "/")]
    assert ("API-001", "/login.php") in r.not_covered and r.fp == [] and r.tn == []


def test_reports_are_written(tmp_path):
    r = ev.score("cawasma", "dvwa", [_f("INF-004", "/.git/HEAD")], GT, covered=None)
    r.scan_seconds = 12.5
    ev.write_reports([r], tmp_path, {"run": "test"})
    assert (tmp_path / "metrics.csv").read_text().startswith("tool,target,tp,fp,fn,tn")
    assert "| cawasma | dvwa |" in (tmp_path / "comparison.md").read_text()
    errors = (tmp_path / "errors.md").read_text()
    assert "**INF-004** (1): dvwa `/.git/HEAD`" in errors
    assert "**API-001** (1): dvwa `/login.php` (not crawled)" in errors   # nothing seen there
