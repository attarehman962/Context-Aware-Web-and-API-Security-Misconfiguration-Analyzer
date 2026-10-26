"""A tiny HTTPS scan target for the vertical-slice demo and its integration test.

Serves one page over HTTPS with a good set of security headers **except
Strict-Transport-Security**, so a scan of it reports exactly one HSTS finding
(HDR-001). Every other path is a 404.

The certificate is made at start-up: a throwaway CA signs a leaf for the given
names/IPs. Only the CA certificate is written out (``--ca-out``); the scanner
trusts it through ``SCAN_CA_BUNDLE``, so certificate verification stays on.
Private keys never leave the process's temporary directory.

    python -m scripts.demo_target --name demo-target --port 8443 --ca-out /certs/demo-ca.pem

Used by docker-compose.demo.yml (target URL ``https://demo-target:8443/``) and
by backend/tests/integration/test_vertical_slice.py.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import ssl
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PAGE = b"""<!doctype html>
<html><head><title>CAWASMA demo target</title></head>
<body><h1>Demo target</h1><p>Served over HTTPS without HSTS.</p></body></html>"""

# Everything the header checks look for, except Strict-Transport-Security.
HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_certificates(names: list[str], ips: list[str]) -> tuple[bytes, bytes, bytes]:
    """Return ``(ca_cert_pem, leaf_cert_pem, leaf_key_pem)``.

    Valid for 90 days: a long-running demo container must not hit expiry, and
    TLS-003 flags certificates that expire within 15 days.
    """
    now = dt.datetime.now(dt.UTC)
    valid = dt.timedelta(days=90)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("CAWASMA demo CA")).issuer_name(_name("CAWASMA demo CA"))
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + valid)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = [x509.DNSName(n) for n in names]
    sans += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name((names or ips)[0])).issuer_name(ca.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + valid)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    return (ca.public_bytes(pem), leaf.public_bytes(pem),
            key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


class _Handler(BaseHTTPRequestHandler):
    server_version = "demo-target"
    sys_version = ""

    def log_message(self, *args: object) -> None:
        pass

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self._send(200, PAGE) if self.path.split("?")[0] == "/" else self._send(404, b"")

    def do_HEAD(self) -> None:  # noqa: N802 - http.server API
        self.do_GET()


def make_server(host: str, port: int, names: list[str], ips: list[str]
                ) -> tuple[ThreadingHTTPServer, bytes]:
    """An HTTPS server bound to ``host:port`` (0 = any free port), and its CA PEM."""
    ca_pem, cert_pem, key_pem = make_certificates(names, ips)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["http/1.1"])
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = Path(tmp, "cert.pem"), Path(tmp, "key.pem")
        cert.write_bytes(cert_pem + ca_pem)
        key.write_bytes(key_pem)
        ctx.load_cert_chain(cert, key)   # read now; the files are deleted on exit
    server = ThreadingHTTPServer((host, port), _Handler)
    server.daemon_threads = True
    server.socket = ctx.wrap_socket(server.socket, server_side=True,
                                    do_handshake_on_connect=False)
    return server, ca_pem


@contextmanager
def running(host: str, *, names: tuple[str, ...] = (), ips: tuple[str, ...] = ()
            ) -> Iterator[tuple[str, bytes]]:
    """Serve on a free port in a thread; yield ``(base_url, ca_pem)``."""
    server, ca_pem = make_server(host, 0, list(names), list(ips))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    shown = f"[{host}]" if ":" in host else host
    try:
        yield f"https://{shown}:{port}/", ca_pem
    finally:
        server.shutdown()
        server.server_close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104 - a container service
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--name", action="append", default=[],
                        help="DNS name for the certificate (repeatable)")
    parser.add_argument("--ca-out", required=True, help="where to write the CA certificate")
    args = parser.parse_args(argv)
    server, ca_pem = make_server(args.host, args.port, args.name or ["localhost"], [])
    out = Path(args.ca_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(ca_pem)
    print(f"demo target on https://{(args.name or ['localhost'])[0]}:{args.port}/ "
          f"(CA certificate: {out})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
