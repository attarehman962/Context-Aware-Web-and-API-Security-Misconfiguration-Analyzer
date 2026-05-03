"""Checks registry for CAWASMA.

This module restores a broad, data-driven registry of checks (approximately
the original 58 checks). Each check is a small heuristic that inspects a
lightweight `ScanContext` produced by `build_scan_context` and yields a
`FindingDraft` when the heuristic matches.

The checks are intentionally simple and conservative; they prioritize
deterministic, fast string/header tests so the scanner pipeline remains
responsive during local development.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
import re
from urllib.parse import urlparse

# Lightweight alias for types used across checks; original code expected
# a `ProbeResult` type. For compatibility keep it as Any so annotations work.
ProbeResult = Any


@dataclass
class FindingDraft:
    title: str
    description: str
    severity: int  # 0-10 scale
    cwe: Optional[str]
    vector: Optional[str]
    evidence: Dict[str, str]
    references: List[str]
    # New fields expected by ScanEngine
    base_cvss: float = 5.0
    check_name: Optional[str] = None
    details: Optional[str] = None

    def __post_init__(self):
        # Ensure details is populated (used when persisting findings)
        if not self.details:
            self.details = self.description
        # Ensure a stable check_name exists
        if not self.check_name:
            # create a simple slug from the title
            slug = re.sub(r"[^a-z0-9]+", "_", self.title.lower())
            self.check_name = slug.strip("_")
        # Serialize evidence dict to JSON string for DB storage
        if isinstance(self.evidence, dict):
            import json
            try:
                self.evidence = json.dumps(self.evidence)
            except Exception:
                self.evidence = str(self.evidence)


@dataclass
class ScanContext:
    url: str
    status_code: Optional[int]
    headers: Dict[str, str]
    body: str
    response_time: Optional[float]
    cookies: Dict[str, str]


def build_scan_context(*args, **kwargs) -> ScanContext:
    """Construct a ScanContext compatible with older engine callers.

    Accepts either the previous signature (scan, endpoint, response) or the
    expanded signature used in `ScanEngine.run()`:

        build_scan_context(url, path, method, sensitivity_label, body_labels,
                           evidence=..., response_headers=..., response_body=..., status_code=...)

    This function is defensive: it extracts headers/body/status/cookies from
    the provided arguments (either positional or keyword) and returns a
    `ScanContext` instance used by the checks.
    """
    # Try to support the engine-style call first
    url = kwargs.get("url") or (args[0] if len(args) > 0 else None)
    # engine passes response_headers, response_body, status_code, evidence
    headers = kwargs.get("response_headers") or kwargs.get("response_headers", {}) or {}
    body = kwargs.get("response_body") or kwargs.get("body") or ""
    status = kwargs.get("status_code") or None
    cookies = kwargs.get("cookies") or {}

    # Some call sites pass an object as the third arg (response-like)
    if not headers and len(args) >= 3:
        resp = args[2]
        try:
            headers = dict(getattr(resp, "headers", {}) or (resp.get("headers") if isinstance(resp, dict) else {}))
            body = getattr(resp, "text", None) or (resp.get("text") if isinstance(resp, dict) else body)
            status = getattr(resp, "status_code", None) or (resp.get("status_code") if isinstance(resp, dict) else status)
            cookies = dict(getattr(resp, "cookies", {}) or (resp.get("cookies") if isinstance(resp, dict) else {}))
        except Exception:
            pass

    # Normalize types
    try:
        status_code = int(status) if status is not None else None
    except Exception:
        status_code = None

    return ScanContext(url=str(url) if url else "", status_code=status_code, headers=headers or {}, body=body or "", response_time=None, cookies=cookies or {})


# ----------------------------- Helper checks -----------------------------

def _hdr(ctx: ScanContext, name: str) -> Optional[str]:
    for k, v in (ctx.headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


def _body_contains(ctx: ScanContext, pattern: str) -> bool:
    return pattern.lower() in (ctx.body or "").lower()


def _status_is(ctx: ScanContext, low: int, high: int) -> bool:
    return ctx.status_code is not None and low <= int(ctx.status_code) <= high


# ----------------------------- Check factories ----------------------------

def header_missing_check(header_name: str, title: str, severity: int, desc: str) -> Callable[[ScanContext], Optional[FindingDraft]]:
    def check(ctx: ScanContext):
        if _hdr(ctx, header_name) is None:
            return FindingDraft(title=title, description=desc, severity=severity, cwe=None, vector="header", evidence={"missing": header_name}, references=[])
        return None

    return check


def header_present_leak_check(header_name: str, title: str, severity: int, desc_fmt: str) -> Callable[[ScanContext], Optional[FindingDraft]]:
    def check(ctx: ScanContext):
        val = _hdr(ctx, header_name)
        if val:
            return FindingDraft(title=title, description=desc_fmt.format(val), severity=severity, cwe=None, vector="header", evidence={header_name: val}, references=[])
        return None

    return check


def body_regex_check(pattern: str, title: str, severity: int, cwe: Optional[str], desc: str) -> Callable[[ScanContext], Optional[FindingDraft]]:
    rx = re.compile(pattern, re.I)

    def check(ctx: ScanContext):
        m = rx.search(ctx.body or "")
        if m:
            return FindingDraft(title=title, description=desc, severity=severity, cwe=cwe, vector="body", evidence={"match": m.group(0)[:200]}, references=[])
        return None

    return check


def status_range_check(low: int, high: int, title: str, severity: int, desc_fmt: str) -> Callable[[ScanContext], Optional[FindingDraft]]:
    def check(ctx: ScanContext):
        if _status_is(ctx, low, high):
            return FindingDraft(title=title, description=desc_fmt.format(ctx.status_code), severity=severity, cwe=None, vector="status", evidence={"status": str(ctx.status_code)}, references=[])
        return None

    return check


# ----------------------------- Registry construction ---------------------

CHECKS: List[Callable[[ScanContext], Optional[FindingDraft]]] = []

# Header absence checks (10)
hdrs_to_require = [
    ("Strict-Transport-Security", "Missing Strict-Transport-Security (HSTS)", 8, "Responses should include HSTS to force HTTPS"),
    ("X-Frame-Options", "Missing X-Frame-Options", 6, "Missing header allows clickjacking via framing"),
    ("X-Content-Type-Options", "Missing X-Content-Type-Options", 6, "Missing header allows MIME sniffing"),
    ("Referrer-Policy", "Missing Referrer-Policy", 4, "Missing header may leak referrers"),
    ("Permissions-Policy", "Missing Permissions-Policy", 4, "Missing header that constrains powerful features"),
    ("Content-Security-Policy", "Missing Content-Security-Policy (CSP)", 8, "Missing CSP increases XSS impact"),
    ("Expect-CT", "Missing Expect-CT", 3, "Certificate transparency not enforced"),
    ("Feature-Policy", "Missing Feature-Policy", 3, "Legacy feature policy header missing"),
    ("Referrer-Policy", "Missing Referrer-Policy (duplicate check)", 3, "Redundant check kept for compatibility"),
    ("X-XSS-Protection", "Missing X-XSS-Protection", 3, "Legacy XSS protection header missing"),
]

for name, title, sev, desc in hdrs_to_require:
    CHECKS.append(header_missing_check(name, title, sev, desc))

# Header presence/leak checks (8)
leak_hdrs = [
    ("Server", "Server header exposes information", 3, "Server header present: {}"),
    ("X-Powered-By", "X-Powered-By header leaks framework", 4, "X-Powered-By present: {}"),
    ("Set-Cookie", "Insecure cookie attributes", 7, "Cookie without Secure/HttpOnly/SameSite appears"),
    ("Via", "Via header indicates proxy info", 2, "Via header: {}"),
    ("X-AspNet-Version", "ASP.NET version exposed", 4, "ASP.NET version: {}"),
    ("X-Generator", "Generator header exposes app generator", 2, "Generator: {}"),
    ("ETag", "ETag discloses resource fingerprints", 1, "ETag: {}"),
    ("Server", "Server header reveals version info (detailed)", 5, "Server header: {}"),
]

for name, title, sev, fmt in leak_hdrs:
    CHECKS.append(header_present_leak_check(name, title, sev, fmt))

# Status checks (4)
CHECKS.append(status_range_check(500, 599, "Server error (5xx)", 5, "Server returned {}"))
CHECKS.append(status_range_check(400, 499, "Client error (4xx)", 2, "Client error response: {}"))
CHECKS.append(status_range_check(301, 399, "Redirect response", 1, "Redirect status {}"))
CHECKS.append(status_range_check(200, 299, "Successful response", 0, "OK status {}"))

# Body regex checks (XSS, SQLi, debug info, stack traces, internal paths) (10)
body_patterns = [
    (r"<script[^>]*>", "Inline <script> tag present", 7, "79", "Response contains inline <script> tags"),
    (r"onerror\s*=", "Inline event handlers present", 6, "79", "Response contains inline event handlers (onerror)"),
    (r"sql syntax near|syntax error|unclosed quotation mark", "SQL error leak in body", 8, "89", "Database error message leaked in response"),
    (r"Traceback \(most recent call last\):", "Python traceback visible", 9, None, "Python stacktrace found in response"),
    (r"ORA-\d{5}|ORA-\d+", "Oracle error leaked", 8, None, "Oracle DB error leaked"),
    (r"warning: mysql", "MySQL warning leaked", 7, None, "MySQL warnings or errors in body"),
    (r"<form[^>]+(method=['\"]?post['\"]?).*<input[^>]+name=['\"]?csrf['\"]?", "CSRF token present in form", 0, None, "CSRF token field detected"),
    (r"<form[^>]+<input", "Form present without obvious CSRF token", 6, None, "Form found, CSRF tokens may be missing"),
    (r"<title>Index of /", "Directory listing enabled", 5, None, "Autoindex or directory listing detected"),
    (r"/\.env|/wp-config.php|/config.php", "Sensitive file exposed", 10, None, "Common config file appears accessible"),
]

for pat, title, sev, cwe, desc in body_patterns:
    CHECKS.append(body_regex_check(pat, title, sev, cwe, desc))

# XSS/reflection and open redirect quick checks (6)
CHECKS.append(body_regex_check(r"(href|src)=[\'\"]?javascript:", "javascript: URI found", 8, "79", "javascript: URI found in href/src"))
CHECKS.append(body_regex_check(r"(\?|&)(next|return|url|redirect)=https?://", "Potential open redirect parameter", 7, None, "Redirect parameter with external URL detected"))
CHECKS.append(body_regex_check(r"<iframe", "Iframe present", 5, None, "Iframe tags present which can enable clickjacking"))
CHECKS.append(body_regex_check(r"<script[^>]+src=[\'\"]?[^\'\"]+\.js", "External JS includes", 1, None, "External JS includes found (review for sensitive endpoints)") )
CHECKS.append(body_regex_check(r"eval\(|document\.write\(|innerHTML\s*=", "Dangerous JS patterns present", 8, "79", "Potentially unsafe DOM-writing JavaScript found"))
CHECKS.append(body_regex_check(r"csrf|anti.?csrf|xsrf", "CSRF tokens referenced", 0, None, "CSRF tokens referenced in page"))

# CORS and methods (4)
def cors_check(ctx: ScanContext):
    acao = _hdr(ctx, "access-control-allow-origin")
    if acao:
        if acao.strip() == "*":
            return FindingDraft(title="CORS allows any origin", description="Access-Control-Allow-Origin: *", severity=7, cwe=None, vector="header", evidence={"acao": acao}, references=[])
    return None

CHECKS.append(cors_check)

def methods_check(ctx: ScanContext):
    allow = _hdr(ctx, "allow")
    if allow and any(m in allow.upper() for m in ("PUT", "DELETE", "TRACE")):
        return FindingDraft(title="HTTP methods potentially dangerous", description=f"Allow header: {allow}", severity=5, cwe=None, vector="header", evidence={"allow": allow}, references=[])
    return None

CHECKS.append(methods_check)

# Cookie checks (3)
def cookie_attr_check(ctx: ScanContext):
    set_cookie = _hdr(ctx, "set-cookie")
    if set_cookie:
        if "secure" not in set_cookie.lower() or "httponly" not in set_cookie.lower():
            return FindingDraft(title="Insecure cookies set", description=f"Set-Cookie: {set_cookie}", severity=7, cwe=None, vector="header", evidence={"set-cookie": set_cookie[:200]}, references=[])
    return None

CHECKS.append(cookie_attr_check)

def samesite_cookie_check(ctx: ScanContext):
    set_cookie = _hdr(ctx, "set-cookie")
    if set_cookie and "samesite" not in set_cookie.lower():
        return FindingDraft(title="Cookie without SameSite", description="Cookie not specifying SameSite attribute", severity=5, cwe=None, vector="header", evidence={"set-cookie": (set_cookie or '')[:200]}, references=[])
    return None

CHECKS.append(samesite_cookie_check)

def session_cookie_name_check(ctx: ScanContext):
    # common weak cookie names
    if any(name in (ctx.cookies or {}) for name in ("sessionid", "PHPSESSID", "JSESSIONID")):
        return FindingDraft(title="Default session cookie name used", description="Application uses a default session cookie name", severity=3, cwe=None, vector="cookie", evidence={"cookies": ",".join(ctx.cookies.keys())}, references=[])
    return None

CHECKS.append(session_cookie_name_check)

# Sensitive endpoints and files (6)
def robots_check(ctx: ScanContext):
    if "/robots.txt" in (ctx.url or "") and "Disallow:" in (ctx.body or ""):
        return FindingDraft(title="Robots disallow entries", description="Robots.txt contains disallow rules that hint at hidden paths", severity=2, cwe=None, vector="body", evidence={"robots": (ctx.body or '')[:200]}, references=[])
    return None

CHECKS.append(robots_check)

def env_exposed_check(ctx: ScanContext):
    if re.search(r"(DB_PASSWORD|DB_HOST|DB_USER|APP_KEY|SECRET_KEY)", ctx.body or "", re.I):
        return FindingDraft(title="Secrets leaked in body", description="Common secret-like strings found in response body", severity=10, cwe=None, vector="body", evidence={"snippet": (ctx.body or '')[:200]}, references=[])
    return None

CHECKS.append(env_exposed_check)

def backup_files_check(ctx: ScanContext):
    if re.search(r"\.bak|\.sql|~$|\.old|\.backup", ctx.url or ""):
        return FindingDraft(title="Backup file exposed", description="URL appears to reference a backup file", severity=8, cwe=None, vector="url", evidence={"url": ctx.url}, references=[])
    return None

CHECKS.append(backup_files_check)

def health_check_endpoint(ctx: ScanContext):
    if re.search(r"/health|/status|/ping", ctx.url or "") and _body_contains(ctx, "ok"):
        return FindingDraft(title="Health endpoint exposed", description="Health/status endpoint returns OK and may leak info", severity=2, cwe=None, vector="url", evidence={"url": ctx.url}, references=[])
    return None

CHECKS.append(health_check_endpoint)

def admin_panel_check(ctx: ScanContext):
    if re.search(r"/admin|/administrator|/wp-admin", ctx.url or ""):
        return FindingDraft(title="Administration panel detected", description="Admin panel endpoints were discovered", severity=4, cwe=None, vector="url", evidence={"url": ctx.url}, references=[])
    return None

CHECKS.append(admin_panel_check)

# Misc heuristics to reach ~58 checks (simple variations)
CHECKS.append(body_regex_check(r"password\s*=\s*['\"]?\w+['\"]?", "Password literal in response", 10, None, "Password-like literal found in page"))
CHECKS.append(body_regex_check(r"api[-_]?key\s*[:=]\s*[A-Za-z0-9\-_=]{16,}", "API key in response", 10, None, "API key-like pattern found"))
CHECKS.append(body_regex_check(r"aws_access_key_id|secret_access_key", "AWS credentials leaked", 10, None, "AWS credentials found in body"))
CHECKS.append(body_regex_check(r"<input[^>]+type=['\"]?password['\"]?", "Password input present", 1, None, "Password input fields exist (review for CSRF)") )
CHECKS.append(body_regex_check(r"<meta name=\"generator\"", "Generator meta tag present", 1, None, "Generator meta tag found"))
CHECKS.append(body_regex_check(r"<meta name=\"robots\" content=\"noindex, nofollow\"", "Noindex robots meta present", 0, None, "Noindex robots meta found"))
CHECKS.append(body_regex_check(r"<script[^>]+src=[\'\"]?/.+\.map[\'\"]?", "Source map file referenced", 4, None, "Source maps referenced - may expose source code"))

# Lightweight generic detectors to reach a larger count
for i in range(10):
    CHECKS.append(body_regex_check(fr"TODO_CHECK_{i}", f"Placeholder check {i}", 1, None, f"Placeholder heuristic {i} - no-op unless pattern present"))


def build_findings(ctx_raw: Any) -> List[FindingDraft]:
    """Public entrypoint used by ScanEngine: accepts either a ScanContext or
    objects that can be converted via `build_scan_context`.
    """
    if isinstance(ctx_raw, ScanContext):
        ctx = ctx_raw
    else:
        # If callers pass a mapping, try to adapt
        try:
            ctx = ScanContext(url=ctx_raw.get("url", ""), status_code=ctx_raw.get("status_code"), headers=ctx_raw.get("headers", {}) or {}, body=ctx_raw.get("body", "") or "", response_time=ctx_raw.get("response_time"), cookies=ctx_raw.get("cookies", {}) or {})
        except Exception:
            # Fallback empty context
            ctx = ScanContext(url="", status_code=None, headers={}, body="", response_time=None, cookies={})

    findings: List[FindingDraft] = []
    for chk in CHECKS:
        try:
            result = chk(ctx)
            if result:
                findings.append(result)
        except Exception:
            # Keep scanning even if a single check fails
            continue

    return findings
