"""Enumerations shared across ORM models and the scanner.

Kept in one module so both the database layer and the scanner pipeline import
the same canonical values (no drift between "CRITICAL" in one place and
"Critical" in another).
"""
from __future__ import annotations

import enum


class ScanStatus(str, enum.Enum):
    """Lifecycle of a scan job: queued -> running -> done | failed."""

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"


class Severity(str, enum.Enum):
    """CVSS severity buckets (spec section 10)."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ContextClass(str, enum.Enum):
    """Endpoint sensitivity classes from the NLP classifier (contribution 1)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DiscoveryMethod(str, enum.Enum):
    """How an endpoint was discovered by the crawler (spec section 18)."""

    SEED = "SEED"              # the original target URL
    HTML = "HTML"             # extracted from HTML (<a>, <form>, <script>)
    JAVASCRIPT = "JAVASCRIPT" # found in JS (fetch/axios/baseURL/api paths)
    WORDLIST = "WORDLIST"     # controlled wordlist probe
    RECURSIVE = "RECURSIVE"   # recursive crawl (depth <= 2)


class FindingCategory(str, enum.Enum):
    """The eight security-check categories (spec section 13)."""

    HEADERS = "HEADERS"
    COOKIES = "COOKIES"
    CORS = "CORS"
    TLS = "TLS"
    REST_API = "REST_API"
    AUTH = "AUTH"
    INFO_DISCLOSURE = "INFO_DISCLOSURE"


class SameSite(str, enum.Enum):
    """Cookie SameSite attribute values."""

    STRICT = "Strict"
    LAX = "Lax"
    NONE = "None"
    UNSET = "UNSET"
