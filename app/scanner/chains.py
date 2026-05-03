"""Exploit chain correlation."""

from __future__ import annotations

from dataclasses import dataclass, field


CHAIN_LIBRARY = [
    {
        "name": "XSS -> Cookie Theft -> Account Takeover",
        "signals": ["missing_csp", "cookie_missing_httponly", "login_no_rate_limit"],
        "score": 9.4,
        "summary": "Script injection can steal cookies and culminate in account takeover.",
    },
    {
        "name": "IDOR -> Data Exposure -> Privilege Abuse",
        "signals": ["api_bola_idor_probe", "api_excessive_data_exposure", "api_object_reference_oracle"],
        "score": 9.1,
        "summary": "Broken object reference combined with over-sharing creates a direct data access chain.",
    },
    {
        "name": "Misconfigured CORS -> Token Exfiltration -> Session Hijack",
        "signals": ["cors_wildcard_with_credentials", "secret.jwt", "cookie_missing_secure"],
        "score": 9.0,
        "summary": "Credential-bearing cross-origin responses can leak tokens and sessions.",
    },
    {
        "name": "Debug Exposure -> Secret Recovery -> Admin Access",
        "signals": ["stack_trace_exposure", "environment_variable_leak", "server_banner_exposure"],
        "score": 8.8,
        "summary": "Debug output and metadata expose secrets that enable privileged access.",
    },
    {
        "name": "Weak Auth -> Enumeration -> Brute Force Success",
        "signals": ["password_reset_enumeration", "login_no_rate_limit", "jwt_weak_signature"],
        "score": 8.9,
        "summary": "Authentication weaknesses allow targeted credential attacks to succeed.",
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
