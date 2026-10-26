"""Scan pipeline -- orchestrates the whole analysis (spec section 19).

Flow per scan:

    seed fetch (unreachable -> ScanError) -> crawl
          -> (host: TLS probe + HTTP->HTTPS check)
          -> for each endpoint: fetch, classify path, classify body, probe
             (OPTIONS / CORS / benign injection), run the checks, score
          -> correlate attack chains -> stats

Two check systems run side by side until every rule has moved:

* spec-registry checks (``checks/registry.py``, ``config/checks.yaml``) are
  scored with CVSS v3.1 environmental metrics (``cvss.score_finding``): the
  base vector plus CR/IR/AR from the endpoint's sensitivity class and body
  signals, so ``final_vector`` recomputes to ``final_score``;
* legacy ``@rule`` checks still use the interim multiplier formula
  (``cvss.compute_score``) and have no ``final_vector``.

This module is database-free: it returns dataclasses. Persistence lives in
``app/services/result_service.py`` and the Celery task. Progress is reported
through an async ``on_progress`` callback so the worker can publish it to Redis.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.core.body_classifier import BodyClassification, classify_body
from app.core.chains import DetectedChain, correlate_chains
from app.core.checks import CheckContext, RawFinding, run_checks, run_spec_checks
from app.core.checks import registry as spec_registry
from app.core.contracts import BodySignal, EndpointInfo
from app.core.crawler import Crawler
from app.core.cvss import compute_score, score_finding
from app.core.engine import HttpEngine, HttpResult
from app.core.sensitivity import get_classifier, raw_tokens
from app.core.tls import TlsProbe, probe_tls
from app.db.models.enums import (
    ContextClass,
    DiscoveryMethod,
    SameSite,
    Severity,
)
from app.services.llm import get_llm_client
from app.utils.logging import get_logger
from app.utils.redaction import redact_headers

logger = get_logger(__name__)

ProgressFn = Callable[[str, int, str], Awaitable[None]]

# Rules whose score should receive the endpoint's response-body bonus.
_BONUS_RULES = {"API-013", "API-003", "INF-001", "INF-003", "INF-005"}
# Rules that represent credential exposure -> force CRITICAL when creds present.
_FORCE_CRIT_RULES = {"API-013", "INF-003"}
# Host-level rules: they read only the host's TLS probe / HTTP->HTTPS check, so
# they are reported once per scan with no endpoint (contract: endpoint_id null),
# not once per endpoint.
_HOST_RULES = {"TLS-001", "TLS-002", "TLS-003", "TLS-004", "TLS-005", "TLS-008"}


class ScanError(Exception):
    """The scan cannot go on (e.g. target unreachable). The message is shown to
    the user as the scan's ``error``, so it must not contain internals."""


@dataclass
class CookieMeta:
    name: str
    value_length: int
    http_only: bool
    secure: bool
    same_site: SameSite
    domain: str | None
    path: str | None


@dataclass
class ScoredFinding:
    raw: RawFinding
    cvss_base_score: float
    context_multiplier: float | None      # interim formula only
    response_bonus: float | None          # interim formula only
    cawasma_final_score: float
    severity: Severity
    context_class: ContextClass | None
    context_confidence: float | None
    endpoint_index: int | None
    # Environmental scoring (spec-registry checks): base vector + CR/IR/AR.
    final_vector: str | None = None
    score_reasons: list[str] = field(default_factory=list)
    evidence: dict | None = None          # structured evidence; else {"text": raw.evidence}
    owasp_map: list[str] = field(default_factory=list)
    cwe_map: list[str] = field(default_factory=list)


@dataclass
class EndpointAnalysis:
    url: str
    path: str
    method: str
    status_code: int | None
    content_type: str | None
    response_time: float | None
    discovered_by: DiscoveryMethod
    context_class: ContextClass
    context_confidence: float
    context_reason: list[str]
    headers: dict[str, str]
    cookies: list[CookieMeta] = field(default_factory=list)
    body_class: BodyClassification | None = None


@dataclass
class ScanResult:
    target: str
    host: str
    endpoints: list[EndpointAnalysis]
    findings: list[ScoredFinding]
    chains: list[DetectedChain]
    tls: TlsProbe | None
    stats: dict


async def _noop(stage: str, percent: int, message: str) -> None:  # default progress
    return None


def _str_attr(attrs: dict[str, str | bool], key: str) -> str | None:
    value = attrs.get(key)
    return value if isinstance(value, str) else None


def _parse_cookies(set_cookie_headers: list[str]) -> list[CookieMeta]:
    metas: list[CookieMeta] = []
    for raw in set_cookie_headers:
        parts = [p.strip() for p in raw.split(";")]
        first = parts[0]
        name, _, value = first.partition("=")
        attrs: dict[str, str | bool] = {}
        for p in parts[1:]:
            k, _, v = p.partition("=")
            attrs[k.lower()] = v or True
        ss_raw = str(attrs.get("samesite", "")).lower()
        same_site = {
            "strict": SameSite.STRICT, "lax": SameSite.LAX, "none": SameSite.NONE,
        }.get(ss_raw, SameSite.UNSET)
        metas.append(CookieMeta(
            name=name.strip(),
            value_length=len(value),
            http_only="httponly" in attrs,
            secure="secure" in attrs,
            same_site=same_site,
            domain=_str_attr(attrs, "domain"),
            path=_str_attr(attrs, "path"),
        ))
    return metas


def body_signals(body: BodyClassification | None) -> set[BodySignal]:
    """The ML-contract signal set for a body classification."""
    if body is None:
        return set()
    flags = {BodySignal.CREDENTIALS: body.credentials, BodySignal.PII: body.pii,
             BodySignal.FINANCIAL: body.financial, BodySignal.INTERNAL_IP: body.internal_ip}
    return {signal for signal, present in flags.items() if present}


def _spec_findings(result: HttpResult, endpoint: EndpointInfo, *, is_target_root: bool,
                   context_class: ContextClass, confidence: float | None,
                   signals: set[BodySignal], ep_index: int) -> list[ScoredFinding]:
    """Run the spec-registry checks and score them with environmental metrics."""
    out: list[ScoredFinding] = []
    for raw in run_spec_checks(result, endpoint, is_target_root=is_target_root):
        spec = spec_registry.spec_for(raw.check_id)
        score = score_finding(raw, context_class, signals)
        text = str(raw.evidence.get("text") or spec.title or raw.check_id)
        out.append(ScoredFinding(
            raw=RawFinding(
                rule_id=raw.check_id, title=spec.title or raw.check_id,
                category=spec.category, base_severity=score.severity_bucket,
                cvss_vector=spec.base_cvss_vector, base_score=score.base_score,
                evidence=text, impact=spec.description,
                recommendation=spec.recommendation or "",
                references=list(spec.references), limitation=spec.limitation,
            ),
            cvss_base_score=score.base_score,
            context_multiplier=None,
            response_bonus=None,
            cawasma_final_score=score.final_score,
            severity=score.severity_bucket,
            context_class=context_class,
            context_confidence=confidence,
            endpoint_index=ep_index,
            final_vector=score.vector,
            score_reasons=list(score.score_reasons),
            evidence={"text": text, **raw.evidence},
            owasp_map=list(spec.owasp),
            cwe_map=list(spec.cwe),
        ))
    return out


async def _probe_endpoint(engine: HttpEngine, ep_url: str, result: HttpResult,
                          is_api: bool) -> dict:
    """Run bounded auxiliary probes; return signals for the check context."""
    signals: dict = {
        "allowed_methods": set(),
        "cors_acao": None, "cors_acac": None, "cors_methods": None,
        "injection_error_reflected": False,
        "graphql_introspection": "__schema" in (result.body or ""),
    }
    # Every probe stays on the endpoint's origin (same_origin_only): a redirect
    # elsewhere must not carry our probes to a host nobody authorised.
    # OPTIONS -> Allow header.
    try:
        opt = await engine.fetch(ep_url, method="OPTIONS", same_origin_only=True)
        allow = opt.headers.get("allow")
        if allow:
            signals["allowed_methods"] = {m.strip().upper() for m in allow.split(",")}
        signals["cors_methods"] = opt.headers.get("access-control-allow-methods")
    except Exception as exc:  # noqa: BLE001
        logger.debug("OPTIONS probe failed: %s", exc)

    probe_origin = "https://cawasma-probe.example"
    # A real CORS preflight: the only response that carries Access-Control-Max-Age.
    try:
        pre = await engine.fetch(ep_url, method="OPTIONS", same_origin_only=True,
                                 extra_headers={"Origin": probe_origin,
                                                "Access-Control-Request-Method": "GET"})
        signals["cors_preflight_acao"] = pre.headers.get("access-control-allow-origin")
        signals["cors_max_age"] = pre.headers.get("access-control-max-age")
        if not signals["cors_methods"]:
            signals["cors_methods"] = pre.headers.get("access-control-allow-methods")
    except Exception as exc:  # noqa: BLE001
        logger.debug("CORS preflight probe failed: %s", exc)

    # CORS probe with a test Origin header.
    try:
        cors = await engine.fetch(ep_url, extra_headers={"Origin": probe_origin},
                                  same_origin_only=True)
        signals["cors_acao"] = cors.headers.get("access-control-allow-origin")
        signals["cors_acac"] = cors.headers.get("access-control-allow-credentials")
        if not signals["cors_methods"]:
            signals["cors_methods"] = cors.headers.get("access-control-allow-methods")
    except Exception as exc:  # noqa: BLE001
        logger.debug("CORS probe failed: %s", exc)

    # Benign injection probe (detection-only) for API-ish endpoints.
    if is_api:
        sep = "&" if urlparse(ep_url).query else "?"
        probe_url = f"{ep_url}{sep}cawasma_probe=%27%22%3C"
        try:
            inj = await engine.fetch(probe_url, same_origin_only=True)
            # Only a 5xx the probe caused: not when the endpoint fails anyway.
            if inj.status_code and inj.status_code >= 500 and (result.status_code or 0) < 500:
                signals["injection_error_reflected"] = True
            elif "cawasma_probe" in (inj.body or "") and any(
                tok in (inj.body or "") for tok in ("SQL", "syntax", "Exception", "Traceback")
            ):
                signals["injection_error_reflected"] = True
        except Exception as exc:  # noqa: BLE001
            logger.debug("injection probe failed: %s", exc)
    return signals


def _host_findings(target: str, seed: HttpResult, tls: TlsProbe | None,
                   http_redirects: bool | None) -> list[ScoredFinding]:
    """The host-level rules, once per scan, with no endpoint or sensitivity class."""
    if tls is None and http_redirects is None:
        return []
    ctx = CheckContext(url=target, path=urlparse(target).path or "/", result=seed,
                       tls=tls, http_scheme_redirects_https=http_redirects)
    out: list[ScoredFinding] = []
    for raw in run_checks(ctx):
        if raw.rule_id not in _HOST_RULES:
            continue
        score = compute_score(raw.base_score, None)
        out.append(ScoredFinding(
            raw=raw, cvss_base_score=score.cvss_base_score,
            context_multiplier=score.context_multiplier,
            response_bonus=score.response_bonus,
            cawasma_final_score=score.cawasma_final_score, severity=score.severity,
            context_class=None, context_confidence=None, endpoint_index=None,
        ))
    return out


async def _check_http_redirect(engine: HttpEngine, host: str) -> bool | None:
    """Return True if http:// redirects to https://, False if not, None if N/A."""
    try:
        res = await engine.fetch(f"http://{host}/")
        if res.error:
            return None
        if res.final_url.startswith("https://"):
            return True
        if any(u.startswith("https://") for u in res.redirect_chain):
            return True
        return False
    except Exception:  # noqa: BLE001
        return None


async def run_pipeline(target: str, on_progress: ProgressFn | None = None,
                       *, probe: bool = True, allow_private: bool = False,
                       crawl_depth: int | None = None,
                       use_wordlist: bool = True,
                       passive_only: bool = False) -> ScanResult:
    """Execute the full scan and return a structured result.

    ``probe=False`` skips the TLS probe, redirect check and active endpoint
    probes. ``passive_only`` (ScanRequest.passive_only) additionally makes the
    engine refuse anything but GET/HEAD and skips the wordlist; the runner
    sets both. ``crawl_depth`` and ``use_wordlist`` bound discovery.

    ``allow_private`` relaxes SSRF loopback/private-IP blocking and is intended
    for tests against a local mock server only.
    """
    report = on_progress or _noop
    host = urlparse(target).hostname or ""
    classifier = get_classifier()
    llm = get_llm_client()  # None unless LLM_ENABLED + API key configured

    await report("initializing", 2, "Preparing scan")
    spec_registry.load_implementations()

    # Passive scans get an engine that can only send GET/HEAD.
    async with HttpEngine(allow_private=allow_private, passive_only=passive_only) as engine:
        # A target that doesn't answer fails the scan instead of "completing"
        # with findings computed from an empty response.
        seed = await engine.fetch(target, method="GET")
        if seed.status_code is None:
            raise ScanError(f"Target unreachable: {seed.error or 'no response'}")

        # --- Discovery ---------------------------------------------------
        await report("crawling", 8, "Discovering endpoints")
        crawler = Crawler(engine, max_depth=crawl_depth, use_wordlist=use_wordlist)
        discovered = await crawler.crawl(target)
        if not discovered:
            discovered = []
        total = max(len(discovered), 1)

        # --- Host-level checks ------------------------------------------
        await report("tls", 12, "Probing TLS configuration")
        port = urlparse(target).port or 443
        tls = (await asyncio.to_thread(probe_tls, host, port, allow_private=allow_private)
               if probe else None)
        http_redirects = await _check_http_redirect(engine, host) if probe else None

        # --- Per-endpoint analysis --------------------------------------
        endpoints: list[EndpointAnalysis] = []
        findings: list[ScoredFinding] = []

        analyzed: set[str] = set()
        for i, de in enumerate(discovered):
            # The scanner only ever GETs: a URL found as both a link and a POST
            # form is the same response, so analyse it once.
            if de.url in analyzed:
                continue
            analyzed.add(de.url)
            pct = 15 + int((i / total) * 70)
            await report("analyzing", pct, f"Analyzing {de.path}")

            result = await engine.fetch(de.url, method="GET")
            expansions = None
            if llm is not None:
                expansions = await llm.expand_abbreviations(raw_tokens(de.path))
            cls = classifier.classify(de.path, extra_expansions=expansions)
            body_class = classify_body(result.body, result.content_type)
            is_api = "/api" in de.path or "json" in (result.content_type or "").lower()

            signals = (await _probe_endpoint(engine, de.url, result, is_api)
                       if probe else {})

            ctx = CheckContext(
                url=de.url, path=de.path, result=result,
                context_class=cls.context_class, body_class=body_class,
                allowed_methods=signals.get("allowed_methods", set()),
                cors_acao=signals.get("cors_acao"),
                cors_acac=signals.get("cors_acac"),
                cors_methods=signals.get("cors_methods"),
                cors_preflight_acao=signals.get("cors_preflight_acao"),
                cors_max_age=signals.get("cors_max_age"),
                tls=tls,
                http_scheme_redirects_https=http_redirects,
                graphql_introspection=signals.get("graphql_introspection", False),
                injection_error_reflected=signals.get("injection_error_reflected", False),
            )

            ep = EndpointAnalysis(
                url=de.url, path=de.path, method=de.method,
                status_code=result.status_code, content_type=result.content_type,
                response_time=result.response_time, discovered_by=de.discovered_by,
                context_class=cls.context_class, context_confidence=cls.confidence,
                context_reason=cls.reason,
                headers=redact_headers(result.headers),
                cookies=_parse_cookies(result.set_cookie_headers),
                body_class=body_class,
            )
            ep_index = len(endpoints)
            endpoints.append(ep)

            findings.extend(_spec_findings(
                result,
                EndpointInfo(url=de.url, path=de.path, method=de.method,
                             status_code=result.status_code,
                             content_type=result.content_type),
                is_target_root=de.url.rstrip("/") == target.rstrip("/"),
                context_class=cls.context_class, confidence=cls.confidence,
                signals=body_signals(body_class), ep_index=ep_index,
            ))
            for raw in run_checks(ctx):
                if raw.rule_id in _HOST_RULES:
                    continue                      # reported once, below
                bonus = body_class.bonus if raw.rule_id in _BONUS_RULES else 0.0
                force = (raw.rule_id in _FORCE_CRIT_RULES) and body_class.credentials
                score = compute_score(
                    raw.base_score, cls.context_class, bonus, force_critical=force,
                )
                findings.append(ScoredFinding(
                    raw=raw,
                    cvss_base_score=score.cvss_base_score,
                    context_multiplier=score.context_multiplier,
                    response_bonus=score.response_bonus,
                    cawasma_final_score=score.cawasma_final_score,
                    severity=score.severity,
                    context_class=cls.context_class,
                    context_confidence=cls.confidence,
                    endpoint_index=ep_index,
                ))

        findings.extend(_host_findings(target, seed, tls, http_redirects))

        # --- Attack-chain correlation -----------------------------------
        await report("correlating", 92, "Correlating attack chains")
        present = {f.raw.rule_id for f in findings}
        chains = correlate_chains(present)

        stats = _build_stats(endpoints, findings, chains)
        await report("completed", 100, "Scan complete")

    return ScanResult(
        target=target, host=host, endpoints=endpoints,
        findings=findings, chains=chains, tls=tls, stats=stats,
    )


def _build_stats(endpoints, findings, chains) -> dict:
    by_sev = {s.value: 0 for s in Severity}
    for f in findings:
        by_sev[f.severity.value] += 1
    return {
        "endpoints": len(endpoints),
        "findings": len(findings),
        "chains": len(chains),
        "by_severity": by_sev,
        "max_score": max((f.cawasma_final_score for f in findings), default=0.0),
    }
