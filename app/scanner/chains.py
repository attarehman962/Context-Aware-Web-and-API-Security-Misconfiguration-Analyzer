"""Exploit chain correlation."""

from __future__ import annotations

from dataclasses import dataclass, field


CHAIN_LIBRARY = [
    {
        "name": "XSS -> Cookie Theft -> Account Takeover",
        "signals": [
            "missing_content_security_policy_csp",
            "inline_script_tag_present",
            "insecure_cookies_set",
        ],
        "score": 9.4,
        "summary": "Script injection can steal cookies and culminate in account takeover.",
    },
    {
        "name": "CORS -> Token Exfiltration -> Session Hijack",
        "signals": [
            "cors_allows_any_origin",
            "secret.jwt",
            "insecure_cookies_set",
        ],
        "score": 9.1,
        "summary": "Cross-origin exposure combined with token leakage can enable session hijack.",
    },
    {
        "name": "Debug Exposure -> Secret Recovery -> Admin Access",
        "signals": [
            "python_traceback_visible",
            "secrets_leaked_in_body",
            "server_header_exposes_information",
        ],
        "score": 9.0,
        "summary": "Debug output and metadata expose secrets that can support privileged access.",
    },
    {
        "name": "Sensitive File -> Backup Exposure -> Credential Recovery",
        "signals": [
            "sensitive_file_exposed",
            "backup_file_exposed",
            "api_key_in_response",
        ],
        "score": 8.8,
        "summary": "Exposed config and backup artifacts can compound into direct credential recovery.",
    },
    {
        "name": "Admin Surface -> Weak Transport -> Session Risk",
        "signals": [
            "administration_panel_detected",
            "missing_strict_transport_security_hsts",
            "insecure_cookies_set",
        ],
        "score": 8.9,
        "summary": "An exposed admin surface without transport and cookie hardening increases takeover risk.",
    },
]


@dataclass
class ChainMatch:
    name: str
    composite_cvss: float
    summary: str
    matched_signals: list[str] = field(default_factory=list)


def correlate(findings: list[dict], body_signals: list[str]) -> list[ChainMatch]:
    signal_pool = {item.get("check_name", "") for item in findings} | set(body_signals)
    matches: list[ChainMatch] = []
    for chain in CHAIN_LIBRARY:
        required = set(chain["signals"])
        matched = sorted(required & signal_pool)
        if len(matched) >= 2:
            matches.append(
                ChainMatch(
                    name=chain["name"],
                    composite_cvss=chain["score"],
                    summary=chain["summary"],
                    matched_signals=matched,
                )
            )
    return sorted(matches, key=lambda item: item.composite_cvss, reverse=True)
