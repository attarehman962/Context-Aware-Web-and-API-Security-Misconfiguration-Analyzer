import json

from app.models import Endpoint, ExploitChain, Finding, Scan
from app.scanner.reports import export_csv, export_json


def test_export_json_serializes_sqlalchemy_models():
    scan = Scan(id=1, target_url="https://example.com", profile="Standard", status="complete", summary="done")
    endpoint = Endpoint(id=2, scan_id=1, url="https://example.com/login", path="/login", method="GET", sensitivity="HIGH")
    finding = Finding(
        id=3,
        scan_id=1,
        endpoint_id=2,
        check_name="missing_hsts",
        title="Missing Strict-Transport-Security",
        severity="HIGH",
        cvss_base=8.0,
        cvss_adjusted=9.6,
        evidence="{}",
        details="HSTS header missing",
    )
    chain = ExploitChain(id=4, scan_id=1, name="Chain", summary="summary", composite_cvss=9.0, evidence="a,b")

    exported = export_json(scan, [endpoint], [finding], [chain])
    payload = json.loads(exported)

    assert payload["scan"]["target_url"] == "https://example.com"
    assert payload["endpoints"][0]["path"] == "/login"
    assert payload["findings"][0]["check_name"] == "missing_hsts"
    assert payload["chains"][0]["name"] == "Chain"


def test_export_csv_outputs_expected_columns():
    finding = Finding(
        title="Missing Strict-Transport-Security",
        severity="HIGH",
        cvss_base=8.0,
        cvss_adjusted=9.6,
        check_name="missing_hsts",
        details="HSTS header missing",
    )

    exported = export_csv([finding])

    assert "title,severity,cvss_base,cvss_adjusted,check_name,details" in exported
    assert "Missing Strict-Transport-Security,HIGH,8.0,9.6,missing_hsts,HSTS header missing" in exported
