from app.scanner.chains import correlate


def test_correlate_matches_current_check_names():
    findings = [
        {"check_name": "missing_content_security_policy_csp", "severity": "HIGH"},
        {"check_name": "inline_script_tag_present", "severity": "HIGH"},
        {"check_name": "insecure_cookies_set", "severity": "HIGH"},
    ]

    matches = correlate(findings, [])

    assert matches
    assert matches[0].name == "XSS -> Cookie Theft -> Account Takeover"
    assert set(matches[0].matched_signals) == {
        "missing_content_security_policy_csp",
        "inline_script_tag_present",
        "insecure_cookies_set",
    }
