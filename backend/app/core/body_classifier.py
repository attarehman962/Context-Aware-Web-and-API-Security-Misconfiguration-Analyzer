"""Response body classifier -- Contribution 3 (spec section 7).

Scans a response body for sensitivity signals and returns the corresponding
CAWASMA response bonus. Credential exposure forces the finding severity to
CRITICAL. Detected secrets are never returned raw -- only a redacted, safe
evidence string.

Detection is regex-based (no model dependency). Credit-card candidates are
validated with the Luhn checksum to cut false positives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.core.cvss import RESPONSE_BONUS
from app.utils.redaction import safe_evidence

# --- Patterns --------------------------------------------------------------
_CRED_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
    re.compile(r"AKIA[0-9A-Z]{16}"),                                                # AWS
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),                             # key
    # SECRET_KEY=..., password: ..., and JSON "password": "..." (quote before ':').
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)"
               r"[\w-]*['\"]?\s*[=:]\s*['\"]?[^\s'\",;&<>]{5,}"),
]
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Grouped numbers (+92 300 1234567, (555) 123-4567, 555-123-4567) or E.164
# (+923001234567). Not any 10+ digit run: that matched every ISO timestamp.
_PHONE = re.compile(
    r"(?<![\w+])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)\s?|\d{3}[\s.-])\d{3}[\s.-]?\d{4}(?!\d)"
    r"|(?<![\w+])\+\d{8,14}(?!\d)")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){13,16}(?!\d)")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
# "total" alone is pagination ("total": 3), so it needs a currency or cents.
_MONEY = re.compile(
    r"(?i)\b(?:balance|amount|price)\b\W{0,5}[\$€£]?\s?\d"
    r"|\btotal\b\W{0,5}(?:[\$€£]\s?\d|\d+\.\d{2}\b)")
# Card brands by prefix (Visa, Mastercard, Amex, Discover); a bare Luhn check
# also passes ~1 in 10 timestamps and ids.
_CARD_PREFIX = re.compile(r"^(?:4|5[1-5]|2[2-7]|3[47]|6(?:011|5))")
_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)


def _iban_ok(candidate: str) -> bool:
    """ISO 13616 mod-97 check, so random uppercase ids don't count as IBANs."""
    rearranged = candidate[4:] + candidate[:4]
    try:
        return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1
    except ValueError:
        return False


def _card_ok(number: str) -> bool:
    digits = "".join(d for d in number if d.isdigit())
    return bool(_CARD_PREFIX.match(digits)) and _luhn_ok(digits)


def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if not (13 <= len(digits) <= 16):
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


@dataclass
class BodyClassification:
    credentials: bool = False
    pii: bool = False
    financial: bool = False
    internal_ip: bool = False
    bonus: float = 0.0
    reasons: list[str] = field(default_factory=list)
    evidence: str | None = None  # redacted + truncated

    @property
    def force_critical(self) -> bool:
        return self.credentials


def classify_body(body: str | None, content_type: str | None = None
                  ) -> BodyClassification:
    """Classify a response body and compute the response bonus."""
    result = BodyClassification()
    if not body:
        return result

    hits: list[str] = []

    if any(p.search(body) for p in _CRED_PATTERNS):
        result.credentials = True
        result.bonus += RESPONSE_BONUS["credentials"]
        result.reasons.append("Credential-like value detected in response")
        hits.append("credentials")

    pii_hit = bool(_EMAIL.search(body) or _SSN.search(body) or _PHONE.search(body))
    if pii_hit:
        result.pii = True
        result.bonus += RESPONSE_BONUS["pii"]
        result.reasons.append("Personally identifiable information detected")
        hits.append("pii")

    financial = bool(_MONEY.search(body)
                     or any(_iban_ok(m) for m in _IBAN.findall(body)))
    if not financial:
        for cand in _CARD_CANDIDATE.findall(body):
            if _card_ok(cand):
                financial = True
                break
    if financial:
        result.financial = True
        result.bonus += RESPONSE_BONUS["financial"]
        result.reasons.append("Financial data detected")
        hits.append("financial")

    if _PRIVATE_IP.search(body):
        result.internal_ip = True
        result.bonus += RESPONSE_BONUS["internal_ip"]
        result.reasons.append("Internal/private IP address detected")
        hits.append("internal_ip")

    if hits:
        # Store only a redacted, truncated snippet -- never the raw secret.
        result.evidence = safe_evidence(body, max_len=300)

    return result
