"""SSRF protection (spec section 16; design notes in docs/engine-security.md).

The scanner fetches user-supplied URLs, so it must never be tricked into
reaching internal infrastructure. Every decision is made on **IP addresses**,
never on hostname strings:

* IP literals in any encoding (decimal ``2130706433``, hex ``0x7f000001``,
  octal ``0177.0.0.1``, short ``127.1``, IPv6, IPv4-mapped/NAT64 IPv6) are
  decoded here and checked without DNS;
* hostnames are resolved and **every** resulting address must be public;
* the HTTP engine connects only to an address validated by this module
  (``app.core.engine.PinnedNetworkBackend``), which defeats DNS rebinding.

``ALLOWED_INTERNAL_HOSTS`` (empty by default) lets named hosts resolve to
private ranges for the evaluation environment. Loopback, link-local, cloud
metadata, multicast, unspecified and reserved addresses are refused even then.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from app.config import settings
from app.utils.validators import default_port

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Cloud metadata endpoints (AWS/GCP/Azure IPv4, AWS IPv6, AWS ECS, Alibaba).
METADATA_IPS = frozenset(
    ipaddress.ip_address(ip)
    for ip in (
        "169.254.169.254",
        "fd00:ec2::254",
        "169.254.170.2",
        "100.100.100.200",
    )
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
# Deprecated IPv6 site-local (RFC 3879): ``ipaddress`` doesn't count it as private,
# but some networks still route it internally (SEC-07).
_SITE_LOCAL = ipaddress.ip_network("fec0::/10")
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
_INET_ATON = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$", re.I)


class SSRFError(Exception):
    """Raised when a target resolves to a disallowed address."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ResolvedTarget:
    host: str
    ips: tuple[str, ...]


def _embedded_ipv4(ip: IPAddress) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 address really points at (mapped or NAT64)."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _ip_is_disallowed(ip: IPAddress, *, internal_ok: bool = False) -> str | None:
    """Reason the IP must be blocked, else None. ``internal_ok`` lets private
    ranges through (ALLOWED_INTERNAL_HOSTS) but nothing more dangerous."""
    inner = _embedded_ipv4(ip)
    if inner is not None:
        reason = _ip_is_disallowed(inner, internal_ok=internal_ok)
        return f"{reason} (via {ip})" if reason else None
    if ip in METADATA_IPS:
        return "cloud metadata address"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_unspecified:
        return "unspecified address (0.0.0.0/::)"
    if ip.is_reserved:
        return "reserved address"
    if internal_ok:
        return None
    if ip.is_private or ip in _SITE_LOCAL:
        return "private address"
    if not ip.is_global:
        return "non-public address (shared, documentation or benchmarking range)"
    return None


def parse_ip_literal(host: str) -> IPAddress | None:
    """Decode ``host`` if it is an IP literal in any form, else None.

    Handles what ``inet_aton`` (and so browsers and curl) accept: 1-4 parts,
    each decimal, ``0x`` hex or leading-zero octal, e.g. ``2130706433``,
    ``0x7f.1``, ``0177.0.0.1``; plus bracketed or bare IPv6.
    """
    h = host.strip().rstrip(".").strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if not _INET_ATON.match(h):
        return None
    try:
        parts = [
            int(p, 16)
            if p.lower().startswith("0x")
            else int(p, 8)
            if len(p) > 1 and p.startswith("0")
            else int(p)
            for p in h.split(".")
        ]
    except ValueError:  # e.g. "09" is not valid octal
        return None
    *head, last = parts
    if any(p > 255 for p in head) or last >= 256 ** (4 - len(head)):
        return None
    value = last
    for i, part in enumerate(head):
        value |= part << (8 * (3 - i))
    return ipaddress.IPv4Address(value)


def is_allowed_internal(host: str) -> bool:
    return host.strip().rstrip(".").lower() in settings.allowed_internal_hosts


def validate_ip(ip_str: str, *, internal_ok: bool = False) -> None:
    """Raise SSRFError if a single IP string is disallowed."""
    ip = parse_ip_literal(ip_str)
    if ip is None:
        raise SSRFError(f"Not a valid IP address: {ip_str}")
    reason = _ip_is_disallowed(ip, internal_ok=internal_ok)
    if reason:
        raise SSRFError(f"Blocked {ip_str}: {reason}.")


def resolve_and_validate(
    host: str, port: int = 443, *, allow_private: bool = False
) -> ResolvedTarget:
    """Resolve ``host`` and validate every resulting IP.

    ``allow_private`` is used ONLY by the test-suite to reach a local mock
    server; production callers always leave it False.
    """
    if not host:
        raise SSRFError("Empty host.")
    name = host.strip().rstrip(".").strip("[]").lower()
    internal_ok = is_allowed_internal(name)

    literal = parse_ip_literal(name)
    if literal is not None:
        if not allow_private:
            validate_ip(str(literal), internal_ok=internal_ok)
        return ResolvedTarget(host=host, ips=(str(literal),))

    if name in _LOCAL_NAMES and not allow_private:
        raise SSRFError(f"Blocked hostname '{name}'.")

    try:
        infos = socket.getaddrinfo(name, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for {host}: {exc}") from None

    # Keep the resolver's order (it is the order the OS would connect in).
    ips = tuple(dict.fromkeys(str(info[4][0]).split("%")[0] for info in infos))
    if not ips:
        raise SSRFError(f"No addresses resolved for {host}.")

    if not allow_private:
        for ip in ips:  # every address, so the OS can't pick a bad one
            literal_ip = parse_ip_literal(ip)
            if literal_ip is None:
                raise SSRFError(f"DNS for {host} returned an invalid address.")
            reason = _ip_is_disallowed(literal_ip, internal_ok=internal_ok)
            if reason:
                # Say what kind of address, never which one: the API would become
                # an oracle for the server's internal DNS (SEC-02).
                kind = reason.split(" (via ")[0]
                raise SSRFError(f"Blocked {host}: it resolves to a {kind}.")

    return ResolvedTarget(host=host, ips=ips)


def validate_url_ssrf(url: str, *, allow_private: bool = False) -> ResolvedTarget:
    """Parse a URL and run the SSRF resolution check on its host."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        raise SSRFError("URL is malformed (host or port).") from None
    if not parsed.hostname:
        raise SSRFError("URL has no host.")
    if port is None:
        port = default_port(parsed.scheme)
    return resolve_and_validate(parsed.hostname, port, allow_private=allow_private)
