"""Attack chains from config/chains.yaml (core/chains.py, docs/chain-templates.md)."""
from __future__ import annotations

from app.core.chains import ChainEndpoint, ChainMember, correlate, load_templates
from app.core.contracts import BodySignal, SensitivityClass

HOST = "shop.example.com"
HIGH, LOW = SensitivityClass.HIGH, SensitivityClass.LOW


def _ep(path: str, cls=LOW, *signals: BodySignal) -> ChainEndpoint:
    return ChainEndpoint(f"https://{HOST}{path}", cls, frozenset(signals))


def _m(check_id: str, endpoint: int | None) -> ChainMember:
    return ChainMember(check_id, endpoint, HOST)


def _codes(members, endpoints) -> list[str]:
    return [c.code for c in correlate(members, endpoints)]


def test_templates_load_from_chains_yaml_and_beat_every_member():
    templates = {t.chain_id: t for t in load_templates()}
    assert set(templates) == {"C001", "C002", "C003", "C004", "C005"}
    assert all(t.composite_cvss_vector for t in templates.values())


def test_no_findings_no_chains():
    assert correlate([], [_ep("/")]) == []


def test_c001_needs_both_groups_on_the_same_host():
    eps = [_ep("/"), _ep("/login", HIGH)]
    assert "C001" in _codes([_m("CKI-001", 1), _m("HDR-013", 0)], eps)   # across endpoints
    assert "C001" not in _codes([_m("CKI-001", 1)], eps)                  # CSP group empty


def test_c002_error_disclosure_plus_banner():
    eps = [_ep("/")]
    assert "C002" in _codes([_m("API-004", 0), _m("HDR-007", 0)], eps)
    assert "C002" not in _codes([_m("HDR-007", 0), _m("HDR-008", 0)], eps)


def test_c003_needs_cors_on_a_sensitive_endpoint_itself():
    eps = [_ep("/api/account", HIGH), _ep("/", LOW)]
    assert "C003" in _codes([_m("COR-002", 0)], eps)
    assert "C003" not in _codes([_m("COR-002", 1)], eps)   # CORS only on a LOW endpoint


def test_c004_uses_a_host_level_member_and_any_sensitive_endpoint_on_the_host():
    eps = [_ep("/", LOW), _ep("/login", HIGH)]
    members = [_m("HDR-001", 0), _m("TLS-005", None)]      # TLS-005 is host-level
    [chain] = [c for c in correlate(members, eps) if c.code == "C004"]
    assert chain.evidence["context"]["endpoint_sensitivity"] == ["HIGH"]
    assert sorted(chain.member_indexes) == [0, 1]
    assert "C004" not in _codes(members, [_ep("/", LOW)])   # no sensitive endpoint on host


def test_c005_needs_credentials_in_the_exposed_response():
    leaking = [_ep("/.env", LOW, BodySignal.CREDENTIALS)]
    assert "C005" in _codes([_m("INF-003", 0)], leaking)
    assert "C005" not in _codes([_m("INF-003", 0)], [_ep("/.env", LOW, BodySignal.PII)])


def test_a_chain_fires_once_per_unit_and_lists_only_its_members():
    eps = [_ep("/a", HIGH), _ep("/b", HIGH)]
    members = [_m("COR-002", 0), _m("COR-002", 1), _m("HDR-007", 1)]
    c003 = [c for c in correlate(members, eps) if c.code == "C003"]
    assert [c.member_indexes for c in c003] == [[0], [1]]   # one per endpoint
    assert c003[0].evidence["scope"] == {"kind": "endpoint", "value": f"https://{HOST}/a"}
    assert c003[0].evidence["groups"] == [["COR-002"]]


def test_chain_score_is_the_composite_vector_score():
    [chain] = [c for c in correlate([_m("INF-003", 0)],
                                    [_ep("/.env", LOW, BodySignal.CREDENTIALS)])
               if c.code == "C005"]
    template = {t.chain_id: t for t in load_templates()}["C005"]
    assert chain.composite_vector == template.composite_cvss_vector
    assert chain.composite_score == template.score
