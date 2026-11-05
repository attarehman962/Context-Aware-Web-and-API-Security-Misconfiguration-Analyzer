"""TLS_INFO weak_ciphers / issues from the data model (docs/project/project-summary.md)."""

from __future__ import annotations

from app.core.checks.base import RawFinding
from app.core.tls import TlsProbe, weak_ciphers
from app.db.models.enums import FindingCategory, Severity
from app.services.result_service import tls_issues


def _raw(rule_id: str, category: FindingCategory) -> RawFinding:
    return RawFinding(
        rule_id,
        rule_id,
        category,
        Severity.HIGH,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        5.9,
    )


def test_weak_ciphers_lists_the_negotiated_cipher_only_when_weak():
    assert weak_ciphers(TlsProbe("x", negotiated_cipher="ECDHE-RSA-DES-CBC3-SHA")) == [
        "ECDHE-RSA-DES-CBC3-SHA"
    ]
    assert weak_ciphers(TlsProbe("x", negotiated_cipher="TLS_AES_256_GCM_SHA384")) == []
    assert weak_ciphers(TlsProbe("x")) == []


def test_tls_issues_are_the_scan_tls_check_ids():
    findings = [
        _raw("TLS-001", FindingCategory.TLS),
        _raw("HDR-003", FindingCategory.HEADERS),
        _raw("TLS-004", FindingCategory.TLS),
        _raw("TLS-001", FindingCategory.TLS),
    ]
    assert tls_issues(findings) == ["TLS-001", "TLS-004"]
