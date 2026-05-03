import pytest

from app.scanner.checks import build_findings, ScanContext


def test_build_findings_detects_missing_headers_and_xss():
    ctx = ScanContext(
        url="http://example.com/login",
        status_code=200,
        headers={"server": "nginx"},
        body="<html><script>alert(1)</script></html>",
        response_time=0.1,
        cookies={},
    )

    findings = build_findings(ctx)
    titles = [f.title for f in findings]

    assert any("Missing Strict-Transport-Security" in t for t in titles)
    assert any("Inline <script> tag present" in t for t in titles)


def test_build_findings_no_false_positives_for_safe_body():
    ctx = ScanContext(
        url="http://example.com/",
        status_code=200,
        headers={"strict-transport-security": "max-age=31536000; includeSubDomains"},
        body="<html><p>Welcome</p></html>",
        response_time=0.05,
        cookies={},
    )
    findings = build_findings(ctx)
    # Should at least not include the HSTS missing finding
    assert not any("Missing Strict-Transport-Security" in f.title for f in findings)
