"""Safe async HTTP engine (spec section 17; design notes in docs/engine-security.md).

Wraps httpx (HTTP/2 enabled) to collect what the checks need from a response,
while enforcing the safety rules:

* **SSRF:** every URL, initial and each redirect hop, is checked by
  ``app.utils.security`` before a request is sent. Redirects are followed
  manually for that reason.
* **DNS rebinding:** the connection itself goes through
  :class:`PinnedNetworkBackend`, which resolves the host, validates every
  address and connects to a validated IP. A name that resolves to a public
  address during the check and to a private one at connect time is refused.
* **Passive mode:** with ``passive_only`` only GET and HEAD are ever sent.
* **Bounded:** a semaphore caps concurrent requests; timeout, retries (GET/HEAD
  only) and a response-size cap come from settings.

A bad target never raises: every outcome is a :class:`ScanResponse`.
"""
from __future__ import annotations

import asyncio
import ssl
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import httpcore
import httpx

from app.config import settings
from app.core.tls import TlsProbe
from app.utils.logging import get_logger
from app.utils.security import SSRFError, resolve_and_validate, validate_url_ssrf
from app.utils.validators import same_origin

logger = get_logger(__name__)

PASSIVE_METHODS = frozenset({"GET", "HEAD"})
_IDEMPOTENT = frozenset({"GET", "HEAD", "OPTIONS"})
_REDIRECTS = (301, 302, 303, 307, 308)


@dataclass
class ScanResponse:
    """One fetch, normalised. Every check consumes this.

    Headers are lowercased; ``body`` is decoded text capped at the size limit
    (``truncated`` tells you if the cap was hit). ``tls`` is a placeholder the
    pipeline fills from the host's TLS probe.
    """

    requested_url: str
    final_url: str
    method: str
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict] = field(default_factory=list)
    body: str = ""
    content_type: str | None = None
    content_length: int | None = None
    response_time: float | None = None
    redirect_chain: list[str] = field(default_factory=list)
    set_cookie_headers: list[str] = field(default_factory=list)
    error: str | None = None
    truncated: bool = False
    tls: TlsProbe | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None

    # Names used by the engine contract (Atta Prompt 4).
    @property
    def url(self) -> str:
        return self.requested_url

    @property
    def status(self) -> int | None:
        return self.status_code

    @property
    def timing(self) -> float | None:
        return self.response_time


HttpResult = ScanResponse   # original name, still used across the checks


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect only to an IP address that has just passed the SSRF check.

    httpcore calls ``connect_tcp(host, ...)`` for every new connection. We
    resolve ``host`` ourselves, validate every address, and hand the inner
    backend a validated IP, so the address we checked is the address we
    connect to (no second DNS lookup an attacker could answer differently).
    TLS still verifies the certificate against the original hostname:
    httpcore passes it separately as ``server_hostname``.
    """

    def __init__(self, inner: Any = None, *, allow_private: bool = False) -> None:
        self._inner = inner if inner is not None else httpcore.AnyIOBackend()
        self._allow_private = allow_private

    async def connect_tcp(self, host: str, port: int,
                          timeout: float | None = None,  # noqa: ASYNC109 - httpcore API
                          local_address: str | None = None,
                          socket_options: Iterable[Any] | None = None) -> Any:
        target = await asyncio.to_thread(
            resolve_and_validate, host, port, allow_private=self._allow_private)
        last_error: Exception | None = None
        for ip in target.ips:                  # all validated; try in resolver order
            try:
                return await self._inner.connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address,
                    socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                last_error = exc
        raise last_error or httpcore.ConnectError(f"could not connect to {host}")

    async def connect_unix_socket(self, path: str,
                                  timeout: float | None = None,  # noqa: ASYNC109 - httpcore API
                                  socket_options: Iterable[Any] | None = None) -> Any:
        raise SSRFError("unix sockets are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _tls_context() -> ssl.SSLContext:
    """Certificate verification is always on. ``SCAN_CA_BUNDLE`` only adds trust
    anchors (the self-signed demo/eval targets); it never disables checks."""
    ctx = ssl.create_default_context()
    if settings.SCAN_CA_BUNDLE:
        ctx.load_verify_locations(cafile=settings.SCAN_CA_BUNDLE)
    return ctx


class HttpEngine:
    """Reusable async HTTP engine backed by one HTTP/2-capable httpx client."""

    def __init__(self, *, allow_private: bool = False, passive_only: bool = False,
                 max_concurrency: int | None = None, timeout: float | None = None,
                 retries: int | None = None, user_agent: str | None = None,
                 max_response_size: int | None = None) -> None:
        # allow_private is for the test-suite only (reach a local mock server).
        self._allow_private = allow_private
        self.passive_only = passive_only
        self._retries = settings.REQUEST_RETRIES if retries is None else retries
        self._retry_backoff = 0.2
        self._max_response_size = max_response_size or settings.MAX_RESPONSE_SIZE
        concurrency = max_concurrency or settings.MAX_CONCURRENT_REQUESTS
        self._semaphore = asyncio.Semaphore(concurrency)

        self._transport = httpx.AsyncHTTPTransport(
            http2=True,
            verify=_tls_context(),
            limits=httpx.Limits(max_connections=concurrency,
                                max_keepalive_connections=concurrency),
        )
        # httpx doesn't expose the network backend; httpcore's pool reads it from
        # this attribute (tested in test_engine_safety.py so an upgrade can't
        # silently drop the pinning).
        self._transport._pool._network_backend = PinnedNetworkBackend(
            allow_private=allow_private)
        self._client = httpx.AsyncClient(
            transport=self._transport,
            follow_redirects=False,           # we follow manually + re-check SSRF
            timeout=timeout or settings.REQUEST_TIMEOUT,
            headers={"User-Agent": user_agent or settings.USER_AGENT},
            trust_env=False,                  # env proxies would bypass the pinning
        )

    async def __aenter__(self) -> HttpEngine:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def fetch(self, url: str, method: str = "GET",
                    extra_headers: dict[str, str] | None = None, *,
                    same_origin_only: bool = False) -> ScanResponse:
        """Fetch ``url`` safely, following redirects with SSRF re-checks.

        ``same_origin_only`` stops at a redirect that leaves the URL's origin and
        returns that redirect response instead: active probes (wordlist, OPTIONS,
        CORS, injection) must only ever reach the host the user authorised.
        """
        method = method.upper()
        result = ScanResponse(requested_url=url, final_url=url, method=method)
        start = time.perf_counter()
        if self.passive_only and method not in PASSIVE_METHODS:
            result.error = f"Blocked by passive mode: {method} not allowed (GET/HEAD only)."
            return result

        current = url
        chain: list[str] = []
        try:
            for _hop in range(settings.MAX_REDIRECTS + 1):
                # SSRF gate on every hop (initial + each redirect target).
                await asyncio.to_thread(validate_url_ssrf, current,
                                        allow_private=self._allow_private)
                resp = await self._send_with_retries(current, method, extra_headers)
                result.status_code = resp.status_code
                result.final_url = current

                if resp.status_code in _REDIRECTS:
                    location = resp.headers.get("location")
                    nxt = str(httpx.URL(current).join(location)) if location else None
                    if nxt is None or (same_origin_only and not same_origin(url, nxt)):
                        self._capture(result, resp)     # report the redirect itself
                        break
                    current = nxt
                    chain.append(current)
                    if resp.status_code == 303:   # 303 -> next request is a GET
                        method = "GET"
                    continue

                self._capture(result, resp)
                break
            else:
                result.error = "Too many redirects."
        except SSRFError as exc:
            result.error = f"SSRF blocked: {exc.reason}"
            logger.warning("SSRF blocked %s: %s", current, exc.reason)
        except httpx.TimeoutException:
            result.error = "Request timed out."
        except httpx.ConnectError as exc:
            result.error = f"Connection error: {exc}"
        except httpx.HTTPError as exc:
            result.error = f"HTTP error: {exc}"
        except Exception as exc:  # noqa: BLE001 - engine must never propagate
            result.error = f"Unexpected error: {exc}"
            logger.exception("engine unexpected error for %s", url)

        result.redirect_chain = chain
        result.response_time = time.perf_counter() - start
        return result

    async def _send_with_retries(self, url: str, method: str,
                                 extra_headers: dict[str, str] | None) -> httpx.Response:
        attempts = 1 + (self._retries if method in _IDEMPOTENT else 0)
        for attempt in range(attempts):
            try:
                async with self._semaphore:
                    return await self._request_capped(url, method, extra_headers)
            except (httpx.TransportError, httpx.TimeoutException):
                if attempt == attempts - 1:
                    raise
                await asyncio.sleep(self._retry_backoff * (attempt + 1))
        raise AssertionError("unreachable")

    async def _request_capped(self, url: str, method: str,
                              extra_headers: dict[str, str] | None = None) -> httpx.Response:
        """Issue a streamed request and read at most the size cap."""
        req = self._client.build_request(method, url, headers=extra_headers)
        resp = await self._client.send(req, stream=True)
        try:
            chunks: list[bytes] = []
            total = 0
            truncated = False
            async for chunk in resp.aiter_bytes():
                room = self._max_response_size - total
                if len(chunk) > room:
                    chunks.append(chunk[:room])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
            resp._cawasma_body = b"".join(chunks)  # type: ignore[attr-defined]
            resp._cawasma_truncated = truncated      # type: ignore[attr-defined]
        finally:
            await resp.aclose()
        return resp

    @staticmethod
    def _capture(result: ScanResponse, resp: httpx.Response) -> None:
        body_bytes: bytes = getattr(resp, "_cawasma_body", b"")
        result.truncated = getattr(resp, "_cawasma_truncated", False)
        result.headers = {k.lower(): v for k, v in resp.headers.items()}
        result.content_type = resp.headers.get("content-type")
        result.content_length = len(body_bytes)
        result.body = body_bytes.decode("utf-8", errors="replace")
        result.set_cookie_headers = resp.headers.get_list("set-cookie")
        # Cookies (metadata only; value length captured, not the value).
        for name, value in resp.cookies.items():
            result.cookies.append({"name": name, "value_length": len(value or "")})
