"""Response-body signal classifier (owner: Asim; ML contract 1.1.0).

``analyze(response) -> set[BodySignal]`` is the contract function the engine
calls (docs/cvss-mapping-contract.md). ``detect(response)`` returns what was
found: one :class:`Detection` per hit, with its *kind*, the rule that matched
and **redacted** evidence (``AKIA****WXYZ``). Neither ever returns, logs or
stores a full secret.

Six kinds, mapped onto the four contract signals (adding signals would change
the frozen API contract, so the mapping keeps it unchanged):

=============  ===============  ==============================================
kind           BodySignal       what fires
=============  ===============  ==============================================
credential     CREDENTIALS      password fields (JSON, HTML inputs, .env lines),
                                HTTP Basic credentials, connection strings
secret_key     CREDENTIALS      AWS keys, private-key PEM blocks, JWTs, vendor
                                API keys, generic ``*_key``/``*token`` values
                                that pass an entropy check
pii            PII              emails, phone numbers, Pakistan CNIC, US SSN,
                                person names next to personal fields (spaCy)
financial      FINANCIAL        card numbers (brand prefix + Luhn), IBANs
                                (ISO 13616 mod-97)
internal_ip    INTERNAL_IP      RFC 1918, loopback, link-local (v4 and v6)
stack_trace    (none)           Python/Java/PHP/.NET/Node traces: a disclosure,
                                not sensitive data, so it raises no CVSS
                                requirement (check API-004 reports it)
=============  ===============  ==============================================

Regex first; spaCy NER only to confirm that a value under a name-like key is a
person, and only when the same object also has a personal field (email,
phone, address, date of birth, national id). Without spaCy (INSTALL_ML=false)
that one rule is skipped and everything else works.

Placeholders are ignored, because they are not anybody's data and reporting
them would raise the score of every documentation page:

* emails at reserved/documentation domains (RFC 2606 / 6761: ``example.*``,
  ``*.test``, ``*.invalid``, ``*.localhost``) and stock ones such as
  ``test@test.com``, ``user@domain.com``;
* payment-provider test cards (``4111 1111 1111 1111``, ``4242...``) and the
  example IBANs from the ISO/bank documentation;
* AWS's documentation keys (anything containing ``EXAMPLE``) and template or
  mask values (``your_api_key``, ``${TOKEN}``, ``<password>``, ``****``,
  ``changeme``, ``null``, repeated characters);
* fictional phone numbers (``555-01xx``), repeated or sequential digits, and
  the ``12345-1234567-1`` style CNIC examples;
* password fields whose value is a UI label (``"password": "Password"``,
  ``"Forgot your password?"``): translation files are full of them.

Only text-like content types are scanned (``text/*``, JSON, XML, JavaScript,
form data, YAML, CSV); bodies with no content type are sniffed and skipped if
they look binary. At most :data:`MAX_SCAN_CHARS` characters are read.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from app.core.contracts import BodySignal, ResponseInfo
from app.utils.logging import get_logger

logger = get_logger(__name__)

MAX_SCAN_CHARS = 512_000
MAX_EVIDENCE = 120
_TEXT_TYPES = ("text/", "json", "xml", "javascript", "ecmascript", "x-www-form-urlencoded",
               "yaml", "csv", "graphql")
_MASK = "****"

KIND_SIGNAL: dict[str, BodySignal | None] = {
    "credential": BodySignal.CREDENTIALS,
    "secret_key": BodySignal.CREDENTIALS,
    "pii": BodySignal.PII,
    "financial": BodySignal.FINANCIAL,
    "internal_ip": BodySignal.INTERNAL_IP,
    "stack_trace": None,
}


@dataclass(frozen=True)
class Detection:
    """One hit. ``evidence`` is already redacted and safe to store or show."""

    kind: str
    rule: str
    evidence: str

    @property
    def signal(self) -> BodySignal | None:
        return KIND_SIGNAL[self.kind]


# ------------------------------------------------------------- contract API

def analyze(response: ResponseInfo) -> set[BodySignal]:
    """Sensitive-data signals in ``response.body``. Never raises (contract rule 1)."""
    try:
        return {d.signal for d in detect(response) if d.signal is not None}
    except Exception:  # noqa: BLE001 - contract: return the safe default
        logger.exception("body classifier failed on %s", response.url)
        return set()


def detect(response: ResponseInfo) -> list[Detection]:
    """Every detection in the body, in a fixed order, de-duplicated."""
    text = scannable_text(response)
    if not text:
        return []
    lower = text.lower()
    seen: set[tuple[str, str]] = set()
    out: list[Detection] = []
    for detector, triggers in _DETECTORS:
        # Cheap substring pre-check: skip a detector whose patterns can't match.
        if triggers and not any(t in lower for t in triggers):
            continue
        for d in detector(text):
            if (d.kind, d.evidence) not in seen:
                seen.add((d.kind, d.evidence))
                out.append(d)
    return out


def scannable_text(response: ResponseInfo) -> str:
    """The part of the body worth scanning, or "" for non-text content."""
    body = response.body or ""
    if not body:
        return ""
    ctype = (response.content_type or "").lower()
    # application/octet-stream means "type unknown" (crAPI serves /.env that way):
    # sniff it like a missing type instead of trusting it as binary.
    if ctype and "octet-stream" not in ctype:
        if not any(t in ctype for t in _TEXT_TYPES):
            return ""
    elif _looks_binary(body):
        return ""
    return body[:MAX_SCAN_CHARS]


def _looks_binary(body: str) -> bool:
    sample = body[:4096]
    return "\x00" in sample or sample.count("�") > len(sample) // 10


# --------------------------------------------------------------- redaction

def mask(value: str, keep: int = 4) -> str:
    """``AKIAQ3EGRZ7X2MPLWXYZ`` -> ``AKIA****WXYZ``; short values fully masked."""
    value = value.strip()
    if len(value) <= 2 * keep + 4:
        return _MASK
    return f"{value[:keep]}{_MASK}{value[-keep:]}"


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_EVIDENCE else text[:MAX_EVIDENCE - 1] + "…"


# ------------------------------------------------------------ placeholders

_PLACEHOLDER_VALUE = re.compile(
    r"(?ix)^(?:"
    r"|null|none|nil|undefined|true|false|n/?a|tbd|todo|redacted|hidden|secret|password"
    r"|changeme|change[_-]?me|dummy|test|testing|sample|example|placeholder|default"
    r"|x+|\*+|•+|\.+|-+|_+|0+|1234\d*|abc\d*|qwerty|letmein"
    r"|(?:your|my|the|insert|enter|put)[_ -]?[a-z_ -]*"       # your_api_key, enter password
    r"|<[^>]*>|\[[^\]]*\]|\{\{[^}]*\}\}|\$\{[^}]*\}|%[a-z_]+%|\$[A-Z_]+"   # templates
    r")$")


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"")
    return (bool(_PLACEHOLDER_VALUE.match(v)) or "example" in v.lower()
            or (len(v) >= 4 and len(set(v)) <= 2))        # aaaa, xxxx, 0000 (not "app")


_PLACEHOLDER_EMAIL_DOMAINS = re.compile(
    r"(?i)(?:^|\.)(?:example\.(?:com|org|net)|example|test|invalid|localhost|local"
    r"|domain\.com|email\.com|yourdomain\.com|yourcompany\.com|sample\.com)$")
# Organisational mailboxes (security.txt contacts, privacy desks, no-reply senders) are
# published on purpose and identify no person.
_ROLE_MAILBOXES = re.compile(
    r"(?i)^(?:security|privacy|contact|support|info|hello|help|abuse|webmaster|postmaster"
    r"|hostmaster|sales|press|legal|dpo|gdpr|no-?reply|do-?not-?reply|mailer-daemon)$")
_PLACEHOLDER_EMAILS = {"test@test.com", "user@user.com", "admin@admin.com", "foo@bar.com",
                       "john@doe.com", "jane@doe.com", "me@me.com", "a@b.com"}

# Published payment-provider test numbers (Stripe, Braintree, Adyen, PayPal docs).
_TEST_CARDS = {
    "4111111111111111", "4242424242424242", "4012888888881881", "4000056655665556",
    "4000000000000002", "4000000000000077", "4222222222222", "4012111111111111",
    "5555555555554444", "5105105105105100", "5200828282828210", "2223003122003222",
    "378282246310005", "371449635398431", "378734493671000", "6011111111111117",
    "6011000990139424", "6011000400000000", "3566002020360505", "3530111333300000",
    "30569309025904", "38520000023237", "36227206271667",
}
# Example IBANs from ISO 13616 / bank documentation.
_EXAMPLE_IBANS = {
    "GB82WEST12345698765432", "GB29NWBK60161331926819", "DE89370400440532013000",
    "FR1420041010050500013M02606", "NL91ABNA0417164300", "ES9121000418450200051332",
    "IT60X0542811101000000123456", "CH9300762011623852957", "BE68539007547034",
    "PK36SCBL0000001123456702",
}


# ------------------------------------------------------------- credentials

_PASSWORD_KEY = r"[A-Za-z_]{0,40}?(?:password|passwd|pwd|passphrase|passcode)[A-Za-z_]{0,40}"  # noqa: S105 - a regex
_JSON_PASSWORD = re.compile(rf'(?i)"({_PASSWORD_KEY})"\s*:\s*"((?:[^"\\]|\\.){{1,200}})"')
_HTML_PASSWORD = re.compile(
    r"""(?is)<input\b(?=[^>]*\btype\s*=\s*["']?password\b)[^>]*\bvalue\s*=\s*["']([^"']+)["']""")
_ENV_PASSWORD = re.compile(
    r"(?m)^[ \t]*(?:export[ \t]+)?"
    r"([A-Z][A-Z0-9_]{0,40}?(?:PASSWORD|PASSWD|PWD|PASS)[A-Z0-9_]{0,40})"
    r"\s*[=:]\s*['\"]?([^\s'\"#]+)")
_BASIC_AUTH = re.compile(r"\bBasic\s+([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")
_URL_USERINFO = re.compile(
    r"(?i)\b((?:https?|ftp|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?"
    r"|mssql|sqlserver|jdbc:[a-z0-9]+)://)([^\s:@/\"'<>]+):([^\s@/\"'<>]+)@([^\s/\"'<>?#]+)")
_USERINFO_CACHE: list[Any] = [None, []]


def _userinfo_matches(text: str) -> list[re.Match[str]]:
    """URL-credential matches, searched only around each "://" and computed once
    per body (the credential and PII detectors both need them)."""
    if _USERINFO_CACHE[0] is text:
        return _USERINFO_CACHE[1]
    found: list[re.Match[str]] = []
    idx = text.find("://")
    while idx != -1:
        m = _URL_USERINFO.search(text, max(0, idx - 24), idx + 600)
        if m is not None and m.start() <= idx and (not found or m.start() >= found[-1].end()):
            found.append(m)
        idx = text.find("://", idx + 3)
    _USERINFO_CACHE[:] = [text, found]
    return found


_ADO_PASSWORD = re.compile(
    r"(?i)\b(?:server|data source|host)\s*=[^;\"'<>\n]{1,100};[^\"'<>\n]{0,200}?"
    r"\b(?:password|pwd)\s*=\s*([^;\"'<>\n]+)")


def _looks_like_label(key: str, value: str) -> bool:
    """UI text under a password key ("Password", "Forgot your password?")."""
    v = value.strip()
    if " " in v and re.fullmatch(r"[A-Za-z][A-Za-z ,.'?!:()-]*", v):
        return True
    return v.lower() in key.lower() or bool(re.fullmatch(r"[A-Z][a-z]+", v))


def _credentials(text: str) -> Iterator[Detection]:
    lower = text.lower()
    for m in _JSON_PASSWORD.finditer(text) if '"' in text else ():
        key, value = m.group(1), m.group(2)
        if not _is_placeholder(value) and not _looks_like_label(key, value):
            yield Detection("credential", "json-password-field", f'"{key}": "{_MASK}"')
    for m in _HTML_PASSWORD.finditer(text) if "<input" in lower else ():
        if not _is_placeholder(m.group(1)):
            yield Detection("credential", "html-password-input", f'<input type="password" '
                                                                   f'value="{_MASK}">')
    for m in _ENV_PASSWORD.finditer(text):
        if not _is_placeholder(m.group(2)):
            yield Detection("credential", "env-password", f"{m.group(1)}={_MASK}")
    for m in _BASIC_AUTH.finditer(text) if "basic " in lower else ():
        try:
            decoded = base64.b64decode(m.group(1), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        user, sep, password = decoded.partition(":")
        if sep and user.isprintable() and password and not _is_placeholder(password):
            yield Detection("credential", "http-basic-auth",
                            f"Basic {_MASK} (user {mask(user, 1)})")
    for m in _userinfo_matches(text):
        scheme, user, password, host = m.groups()
        if not _is_placeholder(password):
            rule = "url-credentials" if scheme.lower().startswith(("http", "ftp")) \
                else "connection-string"
            yield Detection("credential", rule, _clip(f"{scheme}{user}:{_MASK}@{host}"))
    has_ado = "password=" in lower or "pwd=" in lower
    for m in _ADO_PASSWORD.finditer(text) if has_ado else ():
        if not _is_placeholder(m.group(1)):
            yield Detection("credential", "connection-string", f"…;Password={_MASK}")


# -------------------------------------------------------------- secret keys

_AWS_KEY_ID = re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16})"
                         r"(?![A-Z0-9])")
_AWS_SECRET = re.compile(r"(?i)aws_?secret_?access_?key[\"']?\s*[=:]\s*[\"']?"
                         r"([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])")
_PEM_PRIVATE = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?"
                          r"PRIVATE KEY(?: BLOCK)?)-----")
_JWT = re.compile(r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,})\.(eyJ[A-Za-z0-9_-]{8,})"
                  r"\.([A-Za-z0-9_-]{16,})(?![A-Za-z0-9_-])")
# One pass for all vendor formats; the named group says which one matched.
_VENDOR_KEY = re.compile(
    r"\b(?:(?P<stripe_secret_key>(?:sk|rk)_live_[A-Za-z0-9]{20,})"
    r"|(?P<github_token>gh[pousr]_[A-Za-z0-9]{36,})"
    r"|(?P<slack_token>xox[abprs]-[A-Za-z0-9-]{10,})"
    r"|(?P<google_api_key>AIza[0-9A-Za-z_-]{35})"
    r"|(?P<sendgrid_key>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"
    r"|(?P<npm_token>npm_[A-Za-z0-9]{36}))\b")
# Generic keys are found keyword-first (fast), then the name and value around it.
_KEY_WORD = re.compile(r"(?i)(?:api[_-]?key|apikey|secret|access[_-]?key|access[_-]?token"
                       r"|auth[_-]?token|client[_-]?secret|private[_-]?key|token)"
                       r"(?=[A-Za-z0-9_.-]{0,40}[\"']?\s*[:=])")
_KEY_REST = re.compile(
    r"""[A-Za-z0-9_.-]{0,40}["']?\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.]{16,256})["']?""")
_KEY_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")


def shannon_entropy(value: str) -> float:
    """Bits per character."""
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _random_looking(value: str) -> bool:
    """Generic-key gate: long, mixed letters and digits, high entropy."""
    return (len(value) >= 16 and shannon_entropy(value) >= 3.5
            and bool(re.search(r"[A-Za-z]", value)) and bool(re.search(r"\d", value))
            and not _is_placeholder(value))


def _jwt_ok(header_b64: str) -> bool:
    try:
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False
    return isinstance(header, dict) and "alg" in header


def _secret_keys(text: str) -> Iterator[Detection]:
    for m in _AWS_KEY_ID.finditer(text):
        if "EXAMPLE" not in m.group(1):
            yield Detection("secret_key", "aws-access-key-id", mask(m.group(1)))
    for m in _AWS_SECRET.finditer(text):
        if "EXAMPLE" not in m.group(1):
            yield Detection("secret_key", "aws-secret-access-key", mask(m.group(1)))
    for m in _PEM_PRIVATE.finditer(text):
        yield Detection("secret_key", "private-key-pem", f"-----BEGIN {m.group(1)}----- {_MASK}")
    for m in _JWT.finditer(text):
        if _jwt_ok(m.group(1)):
            yield Detection("secret_key", "jwt", f"{m.group(1)[:6]}{_MASK}.{_MASK}.{_MASK}")
    found = set()
    for m in _VENDOR_KEY.finditer(text):
        rule = str(m.lastgroup)
        found.add(m.group(rule))
        yield Detection("secret_key", rule.replace("_", "-"), mask(m.group(rule)))
    for kw in _KEY_WORD.finditer(text):
        rest = _KEY_REST.match(text, kw.end())
        if rest is None:
            continue
        begin = kw.start()
        while begin > 0 and kw.start() - begin < 40 and text[begin - 1] in _KEY_NAME_CHARS:
            begin -= 1
        key = text[begin:rest.start(1)].rstrip(" \t\"':=")
        value = rest.group(1)
        if value in found or _JWT.fullmatch(value) or not _random_looking(value):
            continue
        yield Detection("secret_key", "generic-api-key", f"{key}={mask(value)}")


# --------------------------------------------------------------------- PII

_EMAIL = re.compile(r"(?<![\w.+*-])([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*"
                    r"\.([A-Za-z]{2,24}))(?![\w-])")
_FILE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "js", "css", "map", "json"}
_PHONE = re.compile(
    r"(?<![\w+./-])(?:"
    r"\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}"     # +92 300 1234567
    r"|\(\d{3}\)\s?\d{3}[\s.-]\d{4}"                                 # (555) 123-4567
    r"|\d{3}[.-]\d{3}[.-]\d{4}"                                      # 555-123-4567
    r"|03\d{2}[\s-]?\d{7}"                                           # 0300-1234567 (PK mobile)
    r")(?![\w./-]*\d)")
# Pakistan CNIC (5-7-1) and US SSN (3-2-4) in one pass.
_NATIONAL_ID = re.compile(
    r"(?<![\d-])(?:(?P<cnic>\d{5}-\d{7}-\d)"
    r"|(?P<ssn>(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}))(?![\d-])")
_NAME_FIELD = re.compile(
    r'(?i)"(full_?name|first_?name|last_?name|sur_?name|given_?name|family_?name'
    r'|customer_?name|owner_?name|account_?name|holder_?name|display_?name|name)"\s*:\s*'
    r'"([A-Z][a-zA-Z\'-]+(?: [A-Z][a-zA-Z\'-]+){0,3})"')
_PERSONAL_FIELD = re.compile(
    r'(?i)"(?:e-?mail|phone|mobile|tel|address|street|dob|date_?of_?birth|birth_?date'
    r'|ssn|cnic|national_?id|passport)\w*"\s*:')
# JSON display copy: an email quoted in a challenge description or a hint is
# documentation, not someone's record. Only prose values (5+ words) under these
# keys; "email": "..." fields, other keys and HTML pages are scanned as usual.
_PROSE_FIELD = re.compile(
    r'"(?:description|hint|text|help|instructions?|summary|title|label|tooltip|message)"'
    r'\s*:\s*"((?:[^"\\]|\\.){20,5000})"', re.I)
_NAME_WINDOW = 400
_MAX_NAME_CANDIDATES = 20


def _email_placeholder(local: str, domain: str) -> bool:
    addr = f"{local}@{domain}".lower()
    return (addr in _PLACEHOLDER_EMAILS or bool(_PLACEHOLDER_EMAIL_DOMAINS.search(domain))
            or bool(_ROLE_MAILBOXES.match(local)))


def _phone_placeholder(digits: str) -> bool:
    core = digits[-10:]
    return (len(set(digits)) <= 2 or core in "01234567890123456789" or core in "9876543210"
            or bool(re.fullmatch(r"\d*55501\d\d", digits)))      # NANP fictional 555-01xx


def _pii(text: str) -> Iterator[Detection]:
    # "postgres://app:pw@db.internal" is a credential, not the email "pw@db.internal".
    userinfo = [m.span() for m in _userinfo_matches(text)]
    prose = ([m.span(1) for m in _PROSE_FIELD.finditer(text) if m.group(1).count(" ") >= 4]
             if text.lstrip()[:1] in ("{", "[") else [])
    for m in _EMAIL.finditer(text):
        local, domain, tld = m.groups()
        if tld.lower() in _FILE_TLDS or _email_placeholder(local, domain):
            continue
        if any(a <= m.start() < b for a, b in userinfo + prose):
            continue
        yield Detection("pii", "email", f"{local[0]}***@{domain}")
    for m in _PHONE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 10 <= len(digits) <= 15 and not _phone_placeholder(digits):
            yield Detection("pii", "phone", f"{'*' * (len(digits) - 2)}{digits[-2:]}")
    for m in _NATIONAL_ID.finditer(text):
        if m.group("cnic"):
            digits = m.group("cnic").replace("-", "")
            if len(set(digits)) > 2 and digits not in ("1234512345671", "1234567890123"):
                yield Detection("pii", "national-id-cnic", f"*****-*******-{digits[-1]}")
        elif m.group("ssn") not in ("123-45-6789", "078-05-1120"):   # documentation SSNs
            yield Detection("pii", "national-id-ssn", f"***-**-{m.group('ssn')[-4:-2]}**")
    yield from _person_names(text)


def _person_names(text: str) -> Iterator[Detection]:
    candidates = []
    for m in _NAME_FIELD.finditer(text):
        window = text[max(0, m.start() - _NAME_WINDOW):m.end() + _NAME_WINDOW]
        if _PERSONAL_FIELD.search(window):
            candidates.append((m.group(1), m.group(2)))
        if len(candidates) >= _MAX_NAME_CANDIDATES:
            break
    if not candidates:
        return
    nlp = _spacy()
    if nlp is None:          # NER unavailable: this rule needs it, the rest does not
        return
    values = [v for _, v in candidates]
    for (key, value), doc in zip(candidates, nlp.pipe(values), strict=True):
        if any(ent.label_ == "PERSON" for ent in doc.ents):
            initials = " ".join(f"{w[0]}." for w in value.split())
            yield Detection("pii", "person-name", f'"{key}": "{initials}"')


@lru_cache(maxsize=1)
def _spacy() -> Any:
    """spaCy's small English model, NER only; None when not installed."""
    try:
        import spacy

        return spacy.load("en_core_web_sm",
                          exclude=["parser", "lemmatizer", "attribute_ruler", "tagger"])
    except Exception as exc:  # noqa: BLE001 - optional dependency (INSTALL_ML=false)
        logger.info("spaCy unavailable, person-name rule disabled: %s", exc)
        return None


# --------------------------------------------------------------- financial

_CARD = re.compile(r"(?<![\d-])(\d(?:[ -]?\d){12,18})(?![\d-])")
_CARD_BRANDS = [   # (prefix regex, allowed lengths)
    (re.compile(r"^4"), {13, 16, 19}),                                  # Visa
    (re.compile(r"^(?:5[1-5]|2(?:2[2-9]|[3-6]\d|7[01]|720))"), {16}),   # Mastercard
    (re.compile(r"^3[47]"), {15}),                                      # Amex
    (re.compile(r"^(?:6011|65|64[4-9])"), {16, 19}),                    # Discover
    (re.compile(r"^35(?:2[89]|[3-8]\d)"), {16, 19}),                    # JCB
    (re.compile(r"^3(?:0[0-5]|[68])"), {14}),                           # Diners
]
_IBAN = re.compile(r"(?<![A-Z0-9])([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)"
                   r"(?![A-Z0-9])")


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def iban_ok(iban: str) -> bool:
    if not 15 <= len(iban) <= 34:
        return False
    rearranged = iban[4:] + iban[:4]
    return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1


def _financial(text: str) -> Iterator[Detection]:
    for m in _CARD.finditer(text):
        raw = m.group(1)
        if " " in raw and "-" in raw:          # mixed separators: not a card
            continue
        digits = re.sub(r"\D", "", raw)
        if digits in _TEST_CARDS or len(set(digits)) <= 2:
            continue
        if any(p.match(digits) and len(digits) in lengths for p, lengths in _CARD_BRANDS) \
                and luhn_ok(digits):
            yield Detection("financial", "card-number", f"****{digits[-4:]}")
    for m in _IBAN.finditer(text):
        iban = m.group(1).replace(" ", "")
        if iban not in _EXAMPLE_IBANS and iban_ok(iban):
            yield Detection("financial", "iban", f"{iban[:2]}**{_MASK}{iban[-4:]}")


# ------------------------------------------------------------- internal IP

_IPV4 = re.compile(r"(?<![\w.:/-])((?:\d{1,3}\.){3}\d{1,3})(?!\.?\d)(?![\w-])")
_IPV6 = re.compile(r"(?<![\w:])((?:fe80|f[cd][0-9a-f]{2}):(?::?[0-9a-f]{1,4}){1,7}|::1)"
                   r"(?![\w:])", re.I)


def _internal_ips(text: str) -> Iterator[Detection]:
    for pattern in (_IPV4, _IPV6):
        for m in pattern.finditer(text):
            try:
                ip = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue
            if ip.is_loopback:
                yield Detection("internal_ip", "loopback", str(ip))
            elif ip.is_link_local:
                yield Detection("internal_ip", "link-local", str(ip))
            elif ip.is_private and not ip.is_unspecified and _rfc_private(ip):
                yield Detection("internal_ip", "rfc1918" if ip.version == 4 else "ula", str(ip))


_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _rfc_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.version == 6:
        return ip in ipaddress.ip_network("fc00::/7")
    return any(ip in net for net in _RFC1918)


# ------------------------------------------------------------ stack traces

# (language, lowercase markers one of which the trace contains, pattern)
_FRAME = ("\tat ", "    at ", "   at ", "&nbsp;at ", ">at ")
# A frame starts on a new indented line, or, in HTML error pages (Express's
# errorhandler), inside <li>/<br> with &nbsp; indentation.
_SEP = r"(?:\n[ \t]+|(?:</li>\s*)?(?:<li>|<br\s*/?>)(?:\s|&nbsp;|&#160;)*)"
_TRACES = [
    ("python", ("traceback",),
     re.compile(r'Traceback \(most recent call last\):\s*\n\s*File "[^"\n]+", line \d+')),
    ("java", _FRAME,
     re.compile(rf"(?:{_SEP}at [\w$.<>]+\((?:[\w$]+\.(?:java|kt|scala):\d+|Native Method"
                r"|Unknown Source)\)){2}")),
    ("php", (".php", "stack trace"),
     re.compile(r"(?is)(?:fatal error|parse error|warning|uncaught \w+)(?:</b>)?:"
                r".{0,300}? in (?:<b>)?(?:/|[a-z]:\\)[^\s<]+\.php(?:</b>)? on line"
                r"(?: <b>)? ?\d+|Stack trace:\s*(?:<br\s*/?>)?\s*#0 ")),
    ("dotnet", _FRAME,
     re.compile(rf"(?:{_SEP}at [\w.<>`]+\([^)\n]*\)(?: in [^\n<]+:line \d+)?){{2}}")),
    ("node", _FRAME,
     re.compile(rf"(?:{_SEP}at (?:[\w$.<> \[\]]+ )?\(?(?:/|[A-Za-z]:\\|node:|file://)"
                r"[^\s)<]+:\d+:\d+\)?){2}")),
]


def _stack_traces(text: str) -> Iterator[Detection]:
    from app.utils.redaction import redact_text

    lower = text.lower()
    for lang, markers, pattern in _TRACES:
        if not any(mk in lower for mk in markers):
            continue
        m = pattern.search(text)
        if m:
            plain = re.sub(r"<[^>]+>|&nbsp;|&#160;", "\n", m.group(0))   # HTML error pages
            first = next((ln.strip() for ln in plain.splitlines() if ln.strip()), "")
            yield Detection("stack_trace", f"{lang}-stack-trace", _clip(redact_text(first) or ""))


# (detector, lowercase substrings at least one of which its patterns need; () = always)
_DETECTORS: tuple[tuple[Callable[[str], Iterator[Detection]], tuple[str, ...]], ...] = (
    (_credentials, ("pass", "pwd", "basic ", "://")),
    (_secret_keys, ("akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "aipa", "secret",
                    "private key", "eyj", "_live_", "gh", "xox", "aiza", "sg.", "npm_", "key",
                    "token")),
    (_pii, ("@", "+", "(", "-", "name")),
    (_financial, ()),
    (_internal_ips, (".", "::")),
    (_stack_traces, ("traceback", "\tat ", " at ", "error", "exception", "stack trace")),
)
