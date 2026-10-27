"""TLS checks TLS-001..TLS-008 (spec section 13).

These read ``ctx.tls`` (a TlsProbe). If no probe is available the TLS rules are
skipped -- they never fabricate a result.

TLS-005 moved to ``checks/spec/transport.py`` (judged on the HTTP probe).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.checks.base import CheckContext, RawFinding, make, rule
from app.core.tls import weak_ciphers


@rule
def tls_001_legacy(ctx: CheckContext) -> RawFinding | None:
    if not ctx.tls:
        return None
    legacy = [p for p in ctx.tls.protocols_offered
              if p in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")]   # SSLv2/3: only SSLyze sees them
    if legacy:
        return make("TLS-001", f"Legacy protocols offered: {', '.join(legacy)}.")
    return None


@rule
def tls_002_weak_cipher(ctx: CheckContext) -> RawFinding | None:
    if not ctx.tls or not weak_ciphers(ctx.tls):
        return None
    return make("TLS-002", f"Weak cipher negotiated: {ctx.tls.negotiated_cipher}.")


@rule
def tls_003_expiry(ctx: CheckContext) -> RawFinding | None:
    if not ctx.tls or not ctx.tls.cert_not_after:
        return None
    now = datetime.now(UTC)
    if ctx.tls.cert_not_after < now:
        return make("TLS-003", f"Certificate expired on {ctx.tls.cert_not_after:%Y-%m-%d}.")
    if ctx.tls.cert_not_after < now + timedelta(days=15):
        return make("TLS-003", f"Certificate expires soon ({ctx.tls.cert_not_after:%Y-%m-%d}).")
    return None


@rule
def tls_004_self_signed(ctx: CheckContext) -> RawFinding | None:
    if ctx.tls and ctx.tls.is_self_signed:
        return make("TLS-004", "Certificate subject equals issuer (self-signed).")
    return None


@rule
def tls_006_mixed_content(ctx: CheckContext) -> RawFinding | None:
    if ctx.url.startswith("https://") and 'src="http://' in ctx.result.body.lower():
        return make("TLS-006", "HTTPS page references http:// sub-resources.")
    return None


@rule
def tls_007_preload(ctx: CheckContext) -> RawFinding | None:
    hsts = (ctx.header("Strict-Transport-Security") or "").lower()
    if hsts and "preload" not in hsts:
        return make("TLS-007", "HSTS present but without 'preload'.")
    return None


@rule
def tls_008_hostname(ctx: CheckContext) -> RawFinding | None:
    if ctx.tls and ctx.tls.hostname_matches is False:
        return make("TLS-008", "Certificate does not match the requested hostname.")
    return None
