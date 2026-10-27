"""TLS/certificate probing (spec section 13, TLS checks), once per host.

When SSLyze is installed (the default image), it enumerates every protocol
version SSLv2-TLS 1.3 with its accepted cipher suites and validates the
certificate chain against its trust stores; its bundled OpenSSL still speaks
the legacy protocols that a modern system OpenSSL refuses, so "TLS 1.0
offered" is a real answer, not a limitation. The plain ``ssl`` handshake below
still records the negotiated protocol/cipher and certificate facts, and is the
whole probe when SSLyze is absent.

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
    # SSLyze results (empty / None when it did not run)
    accepted_ciphers: list[str] = field(default_factory=list)
    cert_trusted: bool | None = None          # chain verified against a trust store
    scanner: str = "ssl"                      # "sslyze" when SSLyze ran


# Cipher-name fragments that mark a cipher suite as weak (check TLS-002).
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")


def weak_ciphers(probe: TlsProbe) -> list[str]:
    """Weak cipher suites the host accepts (every accepted suite with SSLyze;
    otherwise the negotiated one)."""
    seen = probe.accepted_ciphers or ([probe.negotiated_cipher] if probe.negotiated_cipher else [])
    return sorted({c for c in seen if any(tok in c.upper() for tok in WEAK_CIPHER_TOKENS)})


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

    if not _sslyze_scan(host, ip, port, probe):
        # Legacy protocol probe (bounded, best-effort), to the same validated IP.
        _probe_legacy(host, ip, port, probe)
    return probe


# SSLyze scan command attribute -> protocol name (as ssl.SSLSocket.version() names them)
_SSLYZE_PROTOCOLS = (("ssl_2_0_cipher_suites", "SSLv2"), ("ssl_3_0_cipher_suites", "SSLv3"),
                     ("tls_1_0_cipher_suites", "TLSv1"), ("tls_1_1_cipher_suites", "TLSv1.1"),
                     ("tls_1_2_cipher_suites", "TLSv1.2"), ("tls_1_3_cipher_suites", "TLSv1.3"))


def _sslyze_scan(host: str, ip: str, port: int, probe: TlsProbe) -> bool:
    """Fill protocols, accepted ciphers and chain trust from SSLyze; False if it
    is not installed or the scan failed (the caller falls back)."""
    try:
        from sslyze import (
            ScanCommand,
            ScanCommandAttemptStatusEnum,
            Scanner,
            ServerNetworkConfiguration,
            ServerNetworkLocation,
            ServerScanRequest,
            ServerScanStatusEnum,
        )
    except ImportError:
        return False
    commands = {ScanCommand(attr) for attr, _ in _SSLYZE_PROTOCOLS} | {ScanCommand.CERTIFICATE_INFO}
    request = ServerScanRequest(
        # ip_address pins SSLyze to the address the SSRF guard just validated.
        server_location=ServerNetworkLocation(hostname=host, port=port, ip_address=ip),
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=host, network_timeout=5, network_max_retries=1),
        scan_commands=commands,
    )
    try:
        scanner = Scanner(per_server_concurrent_connections_limit=4,
                          concurrent_server_scans_limit=1)
        scanner.queue_scans([request])
        result = next(iter(scanner.get_results()))
    except Exception as exc:  # noqa: BLE001 - a scanner failure must not end the scan
        logger.info("sslyze failed for %s: %s", host, exc)
        return False
    if result.scan_status != ServerScanStatusEnum.COMPLETED or result.scan_result is None:
        logger.info("sslyze could not connect to %s", host)
        return False
    offered, ciphers = [], []
    for attr, name in _SSLYZE_PROTOCOLS:
        attempt = getattr(result.scan_result, attr)
        if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and \
                attempt.result.accepted_cipher_suites:
            offered.append(name)
            ciphers += [c.cipher_suite.name for c in attempt.result.accepted_cipher_suites]
    cert = result.scan_result.certificate_info
    if (cert.status == ScanCommandAttemptStatusEnum.COMPLETED and cert.result is not None
            and cert.result.certificate_deployments):
        # Trusted if the chain validates against any trust store SSLyze ships
        # (Mozilla, Apple, Microsoft, ...). The hostname match stays our own
        # certificate check above (SSLyze 6 no longer reports it here).
        deployment = cert.result.certificate_deployments[0]
        probe.cert_trusted = any(r.verified_certificate_chain is not None
                                 for r in deployment.path_validation_results)
    probe.protocols_offered = offered
    probe.accepted_ciphers = ciphers
    probe.legacy_probe_inconclusive = False
    probe.scanner = "sslyze"
    return True


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
