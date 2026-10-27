"""TLS probe with SSLyze (core/tls.py), once per host, pinned to the validated IP."""
from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta

import pytest

from app.core.checks import CheckContext, run_checks
from app.core.engine import ScanResponse
from app.core.tls import TlsProbe, probe_tls, weak_ciphers
from scripts import demo_target

needs_sslyze = pytest.mark.skipif(importlib.util.find_spec("sslyze") is None,
                                  reason="SSLyze not installed")


@needs_sslyze
def test_sslyze_lists_protocols_and_ciphers_of_a_modern_server():
    with demo_target.running("127.0.0.1", ips=("127.0.0.1",)) as (url, _ca):
        port = int(url.rsplit(":", 1)[1].strip("/"))
        probe = probe_tls("127.0.0.1", port, allow_private=True)
    assert probe.scanner == "sslyze" and probe.reachable
    assert set(probe.protocols_offered) == {"TLSv1.2", "TLSv1.3"}   # demo allows 1.2+ only
    assert probe.accepted_ciphers and weak_ciphers(probe) == []
    assert probe.cert_trusted is False          # throwaway CA: not in any trust store
    assert probe.legacy_probe_inconclusive is False


def test_tls_probe_refuses_disallowed_addresses_before_sslyze():
    probe = probe_tls("127.0.0.1", 443)          # no allow_private: SSRF guard first
    assert not probe.reachable and probe.scanner == "ssl" and "loopback" in (probe.error or "")


def _ctx(probe: TlsProbe) -> CheckContext:
    seed = ScanResponse(requested_url="https://x.test/", final_url="https://x.test/",
                        method="GET", status_code=200)
    return CheckContext(url="https://x.test/", path="/", result=seed, tls=probe)


def test_legacy_protocol_and_weak_cipher_rules_use_the_full_scan():
    probe = TlsProbe(host="x.test", reachable=True, scanner="sslyze",
                     protocols_offered=["SSLv3", "TLSv1.2"],
                     accepted_ciphers=["TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                                       "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
                     negotiated_cipher="TLS_AES_128_GCM_SHA256",
                     cert_not_after=datetime.now(UTC) + timedelta(days=90))
    ids = {f.rule_id for f in run_checks(_ctx(probe))}
    assert {"TLS-001", "TLS-002"} <= ids        # SSLv3 offered; 3DES accepted
    assert weak_ciphers(probe) == ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
