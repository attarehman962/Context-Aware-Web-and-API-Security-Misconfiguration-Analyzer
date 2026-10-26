"""TLS/certificate probing (spec section 13, TLS checks).

httpx only reports the negotiated connection, so protocol/cipher facts are
gathered here with the low-level ``ssl`` module. Probing is bounded and safe:
short timeouts, one connection per protocol version. Like every other
connection the scanner makes, the probe connects only to an address that has
just passed the SSRF guard (``utils/security.py``), so a rebinding DNS name
cannot point it at an internal service. Where the local OpenSSL
build refuses to even attempt a legacy protocol, that is reported as a
limitation rather than a false negative.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.config import settings
from app.utils.logging import get_logger
from app.utils.security import resolve_and_validate

logger = get_logger(__name__)

_LEGACY_PROTOCOLS = {
    "TLSv1": getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1,
    "TLSv1.1": getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1,
}


@dataclass
class TlsProbe:
    host: str
    port: int = 443
    reachable: bool = False
    negotiated_protocol: str | None = None
    negotiated_cipher: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_after: datetime | None = None
    is_self_signed: bool | None = None
    hostname_matches: bool | None = None
    protocols_offered: list[str] = field(default_factory=list)
    legacy_probe_inconclusive: bool = False
    error: str | None = None


# Cipher-name fragments that mark a cipher suite as weak (check TLS-002).
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")


def weak_ciphers(probe: TlsProbe) -> list[str]:
    """Weak cipher suites observed for the host (today: the negotiated one, if weak)."""
    cipher = probe.negotiated_cipher
    if cipher and any(tok in cipher.upper() for tok in WEAK_CIPHER_TOKENS):
        return [cipher]
    return []


def _parse_cert(der: bytes, host: str, probe: TlsProbe) -> None:
    """Parse a DER certificate for subject/issuer/expiry/self-signed/hostname."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except Exception as exc:  # noqa: BLE001 - parsing is best-effort
        logger.info("cert parse unavailable: %s", exc)
        return

    try:
        cert = x509.load_der_x509_certificate(der)
        probe.cert_subject = cert.subject.rfc4514_string()
        probe.cert_issuer = cert.issuer.rfc4514_string()
        probe.is_self_signed = cert.subject == cert.issuer
        try:
            probe.cert_not_after = cert.not_valid_after_utc
        except AttributeError:  # older cryptography
            probe.cert_not_after = cert.not_valid_after.replace(tzinfo=UTC)

        # Hostname match against SAN dNSNames (IP hosts: SAN iPAddresses);
        # CN only when there is no SAN at all.
        names: list[str] = []
        try:
            literal = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            literal = None
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            if literal is not None:
                probe.hostname_matches = literal in san.value.get_values_for_type(
                    x509.IPAddress)
                return
            names = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            names = [str(cn[0].value)] if cn else []
        probe.hostname_matches = any(_host_matches(host, n) for n in names)
    except Exception as exc:  # noqa: BLE001
        logger.info("cert parse failed for %s: %s", host, exc)


def _host_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.split(".", 1)[-1] == pattern[2:]
    return host == pattern


def probe_tls(host: str, port: int = 443, *, allow_private: bool = False) -> TlsProbe:
    """Probe TLS for a host: negotiated params, cert facts, legacy protocols.

    ``allow_private`` is for tests only, as in the HTTP engine.
    """
    probe = TlsProbe(host=host, port=port)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we inspect the cert ourselves

    try:
        # Raises SSRFError (recorded below) for a disallowed address.
        ip = resolve_and_validate(host, port, allow_private=allow_private).ips[0]
        with socket.create_connection((ip, port), timeout=settings.REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                probe.reachable = True
                probe.negotiated_protocol = ssock.version()
                cipher = ssock.cipher()
                probe.negotiated_cipher = cipher[0] if cipher else None
                der = ssock.getpeercert(binary_form=True)
                if der:
                    _parse_cert(der, host, probe)
    except Exception as exc:  # noqa: BLE001 - probe must not crash the scan
        probe.error = str(exc)
        logger.info("tls probe failed for %s: %s", host, exc)
        return probe

    if probe.negotiated_protocol:
        probe.protocols_offered.append(probe.negotiated_protocol)

    # Legacy protocol probe (bounded, best-effort), to the same validated IP.
    _probe_legacy(host, ip, port, probe)
    return probe


def _probe_legacy(host: str, ip: str, port: int, probe: TlsProbe) -> None:
    for name, version in _LEGACY_PROTOCOLS.items():
        if version is None:
            probe.legacy_probe_inconclusive = True
            continue
        try:
            lctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            lctx.check_hostname = False
            lctx.verify_mode = ssl.CERT_NONE
            lctx.minimum_version = version
            lctx.maximum_version = version
            with socket.create_connection((ip, port), timeout=5) as sock:
                with lctx.wrap_socket(sock, server_hostname=host) as ss:
                    if ss.version() == name:
                        probe.protocols_offered.append(name)
        except (ssl.SSLError, OSError):
            # Server refused the legacy protocol (good) OR our OpenSSL blocked it.
            pass
        except Exception:  # noqa: BLE001
            probe.legacy_probe_inconclusive = True
