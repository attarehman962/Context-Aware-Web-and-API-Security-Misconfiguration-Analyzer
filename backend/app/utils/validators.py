"""Target URL validation.

A target must be a well-formed, HTTPS URL. HTTP-only targets are rejected. This
module does *not* do SSRF checks -- that is ``security.py`` -- it only validates
the shape of the URL. Keeping the two concerns separate makes both testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


class InvalidTargetError(ValueError):
    """Raised when a target URL is malformed or not permitted."""

    def __init__(self, reason: str) -> None:
        """Create the validation error with its reason."""
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ParsedTarget:
    url: str  # normalized URL (no fragment)
    scheme: str
    host: str
    port: int
    path: str


def validate_target_url(raw: str, *, require_https: bool = True) -> ParsedTarget:
    """Validate and normalize a target URL.

    Rejects: empty/malformed input, non-http(s) schemes, http when https is
    required, missing host, and out-of-range ports. Fragments are stripped.
    """
    if not raw or not isinstance(raw, str):
        raise InvalidTargetError("Target URL is empty.")

    raw = raw.strip()
    if len(raw) > 2048:
        raise InvalidTargetError("Target URL is too long.")
    # urlsplit drops CR, LF and tab silently, so the URL scanned would not be the
    # one submitted (SEC-04).
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        raise InvalidTargetError("Target URL contains control characters.")

    try:
        parsed = urlparse(raw)
        port_given = parsed.port
    except ValueError:  # "[::1" (unclosed IPv6), port not a number or > 65535
        raise InvalidTargetError("Target URL is malformed (host or port).") from None

    if parsed.scheme not in ("http", "https"):
        raise InvalidTargetError(f"Unsupported scheme '{parsed.scheme or 'none'}'. Use https://.")
    if require_https and parsed.scheme != "https":
        raise InvalidTargetError("Only HTTPS targets are allowed.")

    if not parsed.hostname:
        raise InvalidTargetError("Target URL has no host.")
    # user:password@ would be stored with the scan and shown in every report (SEC-01).
    if "@" in parsed.netloc:
        raise InvalidTargetError("Target URL must not contain a user name or password.")

    port = default_port(parsed.scheme) if port_given is None else port_given
    if not (1 <= port <= 65535):
        raise InvalidTargetError("Target port is out of range.")

    path = parsed.path or "/"

    # Rebuild without fragment; keep query.
    normalized = urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, ""))

    return ParsedTarget(
        url=normalized,
        scheme=parsed.scheme,
        host=parsed.hostname,
        port=port,
        path=path,
    )


def default_port(scheme: str) -> int:
    """The default port for a scheme (443 for https, else 80)."""
    return 443 if scheme == "https" else 80


def same_origin(url_a: str, url_b: str) -> bool:
    """True if two URLs share scheme, host, and port (same-origin)."""
    a, b = urlparse(url_a), urlparse(url_b)
    a_port = default_port(a.scheme) if a.port is None else a.port
    b_port = default_port(b.scheme) if b.port is None else b.port
    return (a.scheme, a.hostname, a_port) == (b.scheme, b.hostname, b_port)
