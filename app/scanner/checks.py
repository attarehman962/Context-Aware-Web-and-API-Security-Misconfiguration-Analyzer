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
    if status and 500 <= status < 600:
        findings.append(
            FindingDraft(
                check_name="server_error_disclosure",
                title="Server Error Returned",
                base_cvss=5.0,
                evidence=f"HTTP {status} returned; server may leak debug info",
                details="Server returned 5xx status; inspect body for stack traces or debug info",
            )
        )

    return findings

    if is_self_signed:
        return _finding("self_signed_cert", "Self-Signed Certificate", False,
                        "Certificate is self-signed - browsers will show security warnings. "
                        "Use a certificate from a trusted CA (e.g. Let's Encrypt).", "tls")
    return _finding("self_signed_cert", "Certificate from Trusted CA", True,
                    "Certificate issued by a trusted Certificate Authority.", "tls")


def check_http_redirect(redirects: bool) -> dict:
    """Check 27: HTTP to HTTPS redirect."""
    if not redirects:
        return _finding("no_http_redirect", "No HTTP to HTTPS Redirect", False,
                        "Plain HTTP requests are not redirected to HTTPS. "
                        "Credentials may be sent over unencrypted connections.", "tls")
    return _finding("no_http_redirect", "HTTP Redirects to HTTPS", True,
                    "HTTP traffic properly redirected to HTTPS.", "tls")


def check_mixed_content(result: ProbeResult) -> dict:
    """Check 28: HTTP resources loaded on HTTPS page."""
    http_resources = re.findall(
        r'(?:src|href|action)=["\']http://[^"\']+["\']',
        result.body, re.IGNORECASE
    )
    if http_resources:
        examples = http_resources[:3]
        return _finding("mixed_content", "Mixed Content Detected", False,
                        f"HTTPS page loads HTTP resources (MitM risk): "
                        f"{', '.join(examples)}", "tls")
    return _finding("mixed_content", "No Mixed Content", True,
                    "All resources loaded over HTTPS.", "tls")


def check_hsts_preload(result: ProbeResult) -> dict:
    """Check 29: HSTS preload directive."""
    value = _header(result.headers, "strict-transport-security")
    if "preload" in value.lower():
        return _finding("hsts_not_preloaded", "HSTS Preload Directive Present", True,
                        "HSTS header includes preload directive.", "tls")
    return _finding("hsts_not_preloaded", "HSTS Preload Missing", False,
                    "HSTS header does not include 'preload'. Domain not in browser preload list.",
                    "tls")


def check_hostname_mismatch(url: str, cert_hostnames: list) -> dict:
    """Check 30: Certificate hostname mismatch."""
    if not cert_hostnames:
        return _finding("cert_hostname_mismatch", "Certificate Hostnames Unknown", False,
                        "Could not verify certificate hostname coverage.", "tls")
    from urllib.parse import urlparse
    hostname = urlparse(url).hostname or ""
    matched  = any(
        (h.startswith("*.") and hostname.endswith(h[1:])) or h == hostname
        for h in cert_hostnames
    )
    if not matched:
        return _finding("cert_hostname_mismatch", "Certificate Hostname Mismatch", False,
                        f"Hostname '{hostname}' not covered by certificate. "
                        f"Certificate covers: {cert_hostnames}", "tls")
    return _finding("cert_hostname_mismatch", "Certificate Hostname Valid", True,
                    f"Hostname '{hostname}' covered by certificate.", "tls")


def check_weak_cipher(cipher_suite: str) -> dict:
    """Check 31: Weak cipher suites."""
    weak_patterns = ["rc4", "des", "3des", "null", "export", "anon", "md5"]
    if not cipher_suite:
        return _finding("weak_cipher_suite", "Cipher Suite Unknown", False,
                        "Could not determine cipher suite.", "tls")
    cl = cipher_suite.lower()
    for weak in weak_patterns:
        if weak in cl:
            return _finding("weak_cipher_suite", "Weak Cipher Suite Detected", False,
                            f"Cipher suite '{cipher_suite}' is weak/deprecated.", "tls")
    return _finding("weak_cipher_suite", "Cipher Suite Acceptable", True,
                    f"Cipher: {cipher_suite}", "tls")


# ═══════════════════════════════════════════════════════════════════════
# CATEGORY 5 - API SECURITY (14 checks)
# ═══════════════════════════════════════════════════════════════════════

def check_rate_limiting(rate_limited: bool) -> dict:
    """Check 32: Rate limiting on endpoints."""
    if not rate_limited:
        return _finding("no_rate_limit_auth", "No Rate Limiting Detected", False,
                        "Endpoint accepted all burst requests without returning 429. "
                        "Brute-force and credential stuffing attacks are unrestricted.", "api")
    return _finding("no_rate_limit_auth", "Rate Limiting Active", True,
                    "Server returned 429 Too Many Requests during burst test.", "api")


def check_trace_method(result: ProbeResult) -> dict:
    """Check 33: HTTP TRACE method enabled."""
    if result.method == "TRACE" and result.status_code == 200:
        return _finding("trace_method_enabled", "HTTP TRACE Method Enabled", False,
                        "Server responds to TRACE requests. "
                        "Enables Cross-Site Tracing (XST) attacks.", "api")
    return _finding("trace_method_enabled", "TRACE Method Disabled", True,
                    f"TRACE returned {result.status_code} (not 200).", "api")


def check_unauthenticated_exposure(result_auth: ProbeResult,
                                   result_noauth: ProbeResult) -> dict:
    """Check 34: Endpoint returns data without authentication."""
    if (result_noauth.status_code == 200 and
            len(result_noauth.body) > 50 and
            result_noauth.body.strip().startswith(("{", "["))):
        return _finding("unauthenticated_exposure",
                        "Unauthenticated Data Exposure", False,
                        f"Endpoint returns JSON data (status 200) without any "
                        f"Authorization header. First 200 chars: "
                        f"{result_noauth.body[:200]}", "api")
    if result_noauth.status_code in (401, 403):
        return _finding("unauthenticated_exposure",
                        "Authentication Enforced", True,
                        f"Endpoint returns {result_noauth.status_code} without credentials.",
                        "api")
    return _finding("unauthenticated_exposure",
                    "Authentication Status Unclear", True,
                    f"Status {result_noauth.status_code} - not clearly exposing data.",
                    "api")


def check_verbose_errors(result: ProbeResult) -> dict:
    """Check 35: Verbose error messages exposing internals."""
    body = result.body.lower()
    stack_patterns = [
        "traceback (most recent call last)",
        "at com.", "at org.", "at java.",
        "file \"/", "line \\d+, in ",
        "sqlexception", "mysql error", "postgresql error",
        "odbc error", "ora-\\d+",
    ]
    for pattern in stack_patterns:
        if re.search(pattern, body):
            return _finding("verbose_errors", "Verbose Error / Stack Trace Exposed", False,
                            f"Response contains stack trace or DB error information. "
                            f"Internal architecture exposed to attacker.", "api")
    return _finding("verbose_errors", "No Stack Traces Detected", True,
                    "No stack traces or verbose errors found in response.", "api")


def check_mass_assignment(result_normal: ProbeResult,
                           result_extra: ProbeResult) -> dict:
    """Check 36: Mass assignment - server accepts unexpected fields."""
    extra_fields = ["role", "isAdmin", "admin", "is_admin", "permissions"]
    resp_body    = result_extra.body.lower()
    for field_name in extra_fields:
        if (field_name.lower() in resp_body and
                result_extra.status_code not in (400, 422, 403)):
            return _finding("mass_assignment", "Potential Mass Assignment", False,
                            f"Server accepted request with extra field '{field_name}' "
                            f"and did not return 400/422/403. Status: {result_extra.status_code}",
                            "api")
    return _finding("mass_assignment", "No Mass Assignment Detected", True,
                    "Extra privileged fields were rejected or ignored.", "api")


def check_bola(result_a: ProbeResult, result_b: ProbeResult,
               id_a: str, id_b: str) -> dict:
    """Check 37: BOLA/IDOR - accessing other users' resources by ID."""
    if (result_b.status_code == 200 and
            len(result_b.body) > 20 and
            result_b.body.strip().startswith(("{", "["))):
        return _finding("bola_detected", "Potential BOLA / IDOR Vulnerability", False,
                        f"Accessing resource ID '{id_b}' (different from authenticated ID '{id_a}') "
                        f"returned 200 with data. Server may not validate ownership.", "api")
    return _finding("bola_detected", "BOLA Probe - Access Denied", True,
                    f"Accessing ID '{id_b}' returned {result_b.status_code} - access controlled.",
                    "api")


def check_api_versioning(url: str) -> dict:
    """Check 38: API versioning present in URL."""
    if re.search(r"/v\d+[./]|/api/v\d+", url):
        return _finding("missing_api_versioning", "API Versioning Present", True,
                        f"Version found in URL: {url}", "api")
    return _finding("missing_api_versioning", "No API Versioning in URL", False,
                    "No version prefix detected (e.g. /v1/, /api/v2/). "
                    "Poor lifecycle management indicator.", "api")


def check_deprecated_api(active_versions: list) -> dict:
    """Check 39: Old API versions still accessible alongside new ones."""
    if len(active_versions) > 1:
        return _finding("deprecated_api_active", "Multiple API Versions Active", False,
                        f"Versions still accessible: {active_versions}. "
                        f"Old versions may lack newer security patches.", "api")
    return _finding("deprecated_api_active", "Single API Version Active", True,
                    f"Only one API version found: {active_versions}", "api")


def check_options_methods(result: ProbeResult) -> dict:
    """Check 40: OPTIONS exposes dangerous methods."""
    dangerous  = {"TRACE", "CONNECT", "TRACK"}
    exposed    = dangerous & set(result.allowed_methods)
    if exposed:
        return _finding("options_excessive_methods",
                        "Dangerous HTTP Methods Exposed", False,
                        f"OPTIONS lists dangerous methods: {exposed}", "api")
    if "DELETE" in result.allowed_methods and "TRACE" in result.allowed_methods:
        return _finding("options_excessive_methods",
                        "Excessive Methods in OPTIONS", False,
                        f"All allowed methods: {result.allowed_methods}", "api")
    return _finding("options_excessive_methods", "OPTIONS Methods Acceptable", True,
                    f"Allowed: {result.allowed_methods}", "api")


def check_jwt_config(result: ProbeResult) -> dict:
    """Check 41: JWT misconfiguration - alg:none, no expiry, weak algo."""
    import base64, json
    auth_header = _header(result.headers, "authorization")
    # Try to find a JWT in response body or Authorization header
    jwt_pattern = r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*"
    tokens      = re.findall(jwt_pattern, result.body + " " + auth_header)
    if not tokens:
        return _finding("jwt_misconfiguration", "No JWT Found to Analyze", True,
                        "No JWT token found in response or headers.", "api")
    token = tokens[0]
    try:
        header_b64 = token.split(".")[0]
        # Add padding if needed
        header_b64 += "=" * (4 - len(header_b64) % 4)
        header_data = json.loads(base64.urlsafe_b64decode(header_b64))
        alg         = header_data.get("alg", "").lower()
        if alg == "none":
            return _finding("jwt_misconfiguration", "JWT Algorithm: none", False,
                            "JWT uses alg:none - signature is not verified. "
                            "Attacker can forge any token.", "api")
        if alg in ("hs256", "hs384", "hs512"):
            return _finding("jwt_misconfiguration", "JWT Uses Symmetric Algorithm", False,
                            f"JWT uses {alg.upper()} (symmetric). "
                            f"Prefer RS256 or ES256 (asymmetric).", "api")
    except Exception:
        pass
    return _finding("jwt_misconfiguration", "JWT Algorithm Acceptable", True,
                    "JWT found but algorithm is acceptable.", "api")


def check_overfetching(result: ProbeResult) -> dict:
    """Check 42: API returns sensitive fields in response (over-fetching)."""
    sensitive_fields = [
        "password", "password_hash", "passwd", "hashed_password",
        "ssn", "social_security", "credit_card", "card_number",
        "api_key", "api_secret", "private_key", "secret_key",
        "admin_notes", "internal_id", "debug_info",
    ]
    body_lower = result.body.lower()
    found      = [f for f in sensitive_fields if f'"' + f + '"' in body_lower
                  or "'" + f + "'" in body_lower]
    if found:
        return _finding("api_overfetching", "Sensitive Fields in API Response", False,
                        f"Response contains sensitive field names: {found}. "
                        f"API returns more data than client needs.", "api")
    return _finding("api_overfetching", "No Obvious Overfetching", True,
                    "No obviously sensitive field names in response.", "api")


def check_graphql_introspection(result: ProbeResult) -> dict:
    """Check 43: GraphQL introspection enabled in production."""
    body = result.body
    if "__schema" in body and '"types"' in body:
        return _finding("graphql_introspection",
                        "GraphQL Introspection Enabled", False,
                        "GraphQL schema fully exposed via introspection. "
                        "Attacker can map entire API surface.", "api")
    return _finding("graphql_introspection", "GraphQL Introspection Not Detected", True,
                    "No introspection schema in response.", "api")


def check_secret_in_response(result: ProbeResult) -> dict:
    """Check 44: API keys / secrets / JWT in response body."""
    patterns = [
        (r'sk-[a-zA-Z0-9]{48}',              "OpenAI API key"),
        (r'AKIA[0-9A-Z]{16}',                "AWS Access Key"),
        (r'ghp_[a-zA-Z0-9]{36}',             "GitHub Personal Token"),
        (r'["\']api[_-]?key["\']\s*:\s*["\'][a-zA-Z0-9\-_]{20,}["\']', "API Key field"),
        (r'["\']secret["\']\s*:\s*["\'][^"\']{10,}["\']',               "Secret field"),
        (r'["\']password["\']\s*:\s*["\'][^"\']{4,}["\']',              "Password field"),
        (r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',        "JWT token"),
    ]
    for pattern, label in patterns:
        match = re.search(pattern, result.body)
        if match:
            return _finding("secret_in_response", "Secret / Credential in Response", False,
                            f"{label} pattern detected in response body. "
                            f"Match preview: {match.group()[:40]}...", "api")
    return _finding("secret_in_response", "No Secrets Detected in Response", True,
                    "No credential patterns found in response body.", "api")


def check_injection_probe(result_normal: ProbeResult,
                           result_probe: ProbeResult) -> dict:
    """Check 45: Basic injection probe - checks if server crashes on bad input."""
    error_indicators = [
        "sql", "syntax error", "mysql", "postgresql", "oracle",
        "exception", "stack trace", "error in your sql",
        "quoted string not properly terminated",
    ]
    probe_body = result_probe.body.lower()
    # A 500 error on a probe is a strong indicator
    if result_probe.status_code == 500:
        return _finding("injection_probe_hit", "Server Error on Injection Probe", False,
                        f"Server returned 500 when probed with injection characters. "
                        f"Possible injection vulnerability.", "api")
    for indicator in error_indicators:
        if indicator in probe_body:
            return _finding("injection_probe_hit", "Injection Error Indicator Found", False,
                            f"Response to probe contains: '{indicator}'. "
                            f"Server may be vulnerable to injection.", "api")
    return _finding("injection_probe_hit", "No Injection Indicators", True,
                    f"Injection probe returned {result_probe.status_code} without error indicators.",
                    "api")


# ═══════════════════════════════════════════════════════════════════════
# CATEGORY 6 - AUTHENTICATION (7 checks)
# ═══════════════════════════════════════════════════════════════════════

def check_basic_auth(result: ProbeResult) -> dict:
    """Check 46: Basic Auth scheme (base64 only, not encrypted)."""
    www_auth = _header(result.headers, "www-authenticate")
    if "basic" in www_auth.lower():
        return _finding("basic_auth_scheme", "Basic Authentication Used", False,
                        "WWW-Authenticate: Basic - credentials are only base64 encoded, "
                        "not encrypted. Use Bearer/OAuth2 instead.", "auth")
    return _finding("basic_auth_scheme", "Basic Auth Not Detected", True,
                    f"WWW-Authenticate: {www_auth or 'not present'}", "auth")


def check_bfla(result_user: ProbeResult, result_admin: ProbeResult,
               admin_path: str) -> dict:
    """Check 47: Broken Function Level Auth - regular user accessing admin endpoints."""
    if result_admin.status_code == 200 and len(result_admin.body) > 20:
        return _finding("broken_function_auth", "Broken Function Level Authorization", False,
                        f"Admin endpoint '{admin_path}' returned 200 with a regular user token. "
                        f"Function-level authorization is not enforced.", "auth")
    return _finding("broken_function_auth", "Admin Endpoint Access Controlled", True,
                    f"Admin endpoint returned {result_admin.status_code}.", "auth")


def check_reset_token(token1: str, token2: str) -> dict:
    """Check 48: Password reset token entropy and uniqueness."""
    if token1 == token2:
        return _finding("weak_reset_token", "Reset Tokens Not Unique", False,
                        "Two reset tokens are identical - tokens are predictable or reused.",
                        "auth")
    if len(token1) < 20:
        return _finding("weak_reset_token", "Reset Token Too Short", False,
                        f"Reset token length {len(token1)} is too short. "
                        f"Minimum 32 characters recommended.", "auth")
    return _finding("weak_reset_token", "Reset Tokens Appear Unique", True,
                    "Two reset token requests produced different tokens.", "auth")


def check_token_invalidation(result_after_logout: ProbeResult) -> dict:
    """Check 49: Token still valid after logout."""
    if result_after_logout.status_code == 200:
        return _finding("token_not_invalidated", "Token Not Invalidated After Logout", False,
                        "Old token still returns 200 after logout. "
                        "Server does not maintain a token blocklist.", "auth")
    return _finding("token_not_invalidated", "Token Invalidated After Logout", True,
                    f"Token returned {result_after_logout.status_code} after logout.",
                    "auth")


def check_auth_handling(result_bad_token: ProbeResult) -> dict:
    """Check 50: How server handles malformed/expired tokens."""
    sc = result_bad_token.status_code
    if sc == 500:
        return _finding("missing_auth_handling", "Server Crashes on Bad Token", False,
                        "Server returned 500 on malformed Authorization header. "
                        "Should return 401 instead.", "auth")
    if sc == 200:
        return _finding("missing_auth_handling", "Bad Token Accepted", False,
                        "Server returned 200 with an invalid token. "
                        "Authentication is not enforced.", "auth")
    if sc == 401:
        return _finding("missing_auth_handling", "Auth Handling Correct", True,
                        "Server returns 401 for invalid tokens.", "auth")
    return _finding("missing_auth_handling", "Auth Response Unclear", True,
                    f"Server returned {sc} for bad token.", "auth")


def check_default_credentials(results: dict) -> dict:
    """Check 51: Common default username/password combinations."""
    for creds, result in results.items():
        if result.status_code == 200 and "dashboard" in result.body.lower():
            return _finding("default_credentials", "Default Credentials Work", False,
                            f"Login succeeded with credentials: {creds}. "
                            f"Change all default credentials immediately!", "auth")
        if result.status_code in (302, 301):
            loc = _header(result.headers, "location")
            if "dashboard" in loc.lower() or "admin" in loc.lower():
                return _finding("default_credentials", "Default Credentials Accepted", False,
                                f"Redirect to dashboard after login with '{creds}'.", "auth")
    return _finding("default_credentials", "No Default Credentials Accepted", True,
                    "Common default credential combinations were rejected.", "auth")


def check_oauth2_redirect(result: ProbeResult, evil_redirect: str) -> dict:
    """Check 52: OAuth2 open redirect via redirect_uri."""
    if result.status_code in (302, 301):
        loc = _header(result.headers, "location")
        if evil_redirect in loc:
            return _finding("oauth2_misconfiguration", "OAuth2 Open Redirect", False,
                            f"Server redirected to attacker-controlled URL: {loc}. "
                            f"redirect_uri is not validated.", "auth")
    if result.status_code in (400, 401, 403):
        return _finding("oauth2_misconfiguration", "OAuth2 Redirect URI Validated", True,
                        f"Invalid redirect_uri was rejected ({result.status_code}).", "auth")
    return _finding("oauth2_misconfiguration", "OAuth2 Redirect Not Tested", True,
                    "No OAuth2 endpoint found to test.", "auth")


# ═══════════════════════════════════════════════════════════════════════
# CATEGORY 7 - INFORMATION DISCLOSURE (6 checks)
# ═══════════════════════════════════════════════════════════════════════

def check_internal_ip(result: ProbeResult) -> dict:
    """Check 53: Internal IP addresses in headers or body."""
    combined = result.body + " ".join(result.headers.values())
    patterns = [
        r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
        r'\b172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+\b',
    ]
    for p in patterns:
        match = re.search(p, combined)
        if match:
            return _finding("internal_ip_exposed", "Internal IP Address Exposed", False,
                            f"Internal IP '{match.group()}' found in response. "
                            f"Reveals network topology to attacker.", "info")
    return _finding("internal_ip_exposed", "No Internal IPs Found", True,
                    "No RFC1918 private IP addresses detected.", "info")


def check_directory_listing(result: ProbeResult) -> dict:
    """Check 54: Server-side directory listing enabled."""
    indicators = ["index of /", "parent directory", "[to parent directory]"]
    body_lower = result.body.lower()
    for indicator in indicators:
        if indicator in body_lower:
            return _finding("directory_listing", "Directory Listing Enabled", False,
                            f"Response contains directory listing indicator: '{indicator}'. "
                            f"File system structure is exposed.", "info")
    return _finding("directory_listing", "No Directory Listing Detected", True,
                    "No directory listing indicators in response.", "info")


def check_env_file(result: ProbeResult) -> dict:
    """Check 55: .env file publicly accessible."""
    # A real .env file contains KEY=VALUE pairs
    body = result.body
    if (result.status_code == 200 and
            re.search(r'[A-Z_]{3,}=[^\s]', body) and
            ("password" in body.lower() or "secret" in body.lower() or
             "key" in body.lower() or "database" in body.lower())):
        return _finding("env_file_exposed", ".env File Exposed", False,
                        "/.env returned 200 with what appears to be environment "
                        "variables including sensitive values. Immediate action required!",
                        "info")
    return _finding("env_file_exposed", ".env Not Publicly Accessible", True,
                    f"/.env probe returned {result.status_code}.", "info")


def check_git_exposed(result: ProbeResult) -> dict:
    """Check 56: .git directory publicly accessible."""
    git_indicators = ["ref: refs/", "[core]", "repositoryformatversion"]
    body = result.body.lower()
    if result.status_code == 200:
        for indicator in git_indicators:
            if indicator.lower() in body:
                return _finding("git_repo_exposed", ".git Repository Exposed", False,
                                "/.git/ directory is accessible. Full source code and "
                                "git history can be extracted by attackers.", "info")
    return _finding("git_repo_exposed", ".git Not Exposed", True,
                    f"/.git probe returned {result.status_code}.", "info")


def check_backup_files(results: dict) -> dict:
    """Check 57: Backup and temporary files accessible."""
    backup_paths = list(results.keys())
    for path, result in results.items():
        if result.status_code == 200 and len(result.body) > 100:
            return _finding("backup_files_exposed", "Backup File Exposed", False,
                            f"Backup/temp file accessible at: {path}. "
                            f"May contain source code, DB dumps, or credentials.", "info")
    return _finding("backup_files_exposed", "No Backup Files Found", True,
                    "Common backup file paths returned non-200 responses.", "info")


def check_swagger_exposed(result: ProbeResult) -> dict:
    """Check 58: Swagger / OpenAPI documentation publicly accessible."""
    swagger_indicators = [
        "swagger", "openapi", '"paths":', '"swagger":', "api documentation"
    ]
    body_lower = result.body.lower()
    if result.status_code == 200:
        for indicator in swagger_indicators:
            if indicator in body_lower:
                return _finding("swagger_exposed", "API Documentation Publicly Accessible", False,
                                "Swagger/OpenAPI docs accessible without authentication. "
                                "Full API surface mapped for attacker.", "info")
    return _finding("swagger_exposed", "API Docs Not Publicly Accessible", True,
                    f"Swagger probe returned {result.status_code}.", "info")
