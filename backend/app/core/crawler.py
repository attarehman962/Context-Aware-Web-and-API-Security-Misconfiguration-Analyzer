"""Endpoint discovery crawler (spec section 18).

Four strategies sharing one visited-set, bounded by same-origin scope,
MAX_CRAWL_DEPTH, MAX_CRAWL_PAGES (pages fetched) and MAX_ENDPOINTS:

  1. HTML extraction   -- <a href>, <form action> (+ method), <script src>,
                          <link href>, <iframe src>
  2. JavaScript scan   -- fetch()/axios/baseURL and /api/... paths in inline
                          scripts and in fetched script sources
  3. Wordlist probing  -- the small list in app/data/wordlist.txt; skipped in
                          passive mode. A site that answers every path with the
                          same 200 page (SPA catch-all, "soft 404") is detected
                          with one random path first, so its shell page is not
                          reported as /.env, /backup.zip, ...
  4. Recursive crawl   -- BFS to depth <= 2

Off-host links are logged (and kept in ``Crawler.off_host``) but never fetched.

The crawler is decoupled from the database: it returns dataclasses that the
service layer persists later.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from app.config import settings
from app.core.engine import HttpEngine, HttpResult
from app.core.wordlist import PROBE_PATHS
from app.db.models.enums import DiscoveryMethod
from app.utils.logging import get_logger
from app.utils.validators import same_origin

logger = get_logger(__name__)

# JS endpoint-ish patterns (strategy 2).
_JS_PATTERNS = [
    re.compile(r"""fetch\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""axios\.(?:get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""baseURL\s*[:=]\s*['"]([^'"]+)['"]"""),
    re.compile(r"""['"](/api/[A-Za-z0-9_\-/]+)['"]"""),
]


@dataclass
class DiscoveredEndpoint:
    url: str
    path: str
    method: str
    discovered_by: DiscoveryMethod
    status_code: int | None = None
    content_type: str | None = None
    response_time: float | None = None


def _normalize(url: str) -> str:
    """Drop fragment; keep scheme/host/path/query for dedup."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))


class Crawler:
    def __init__(self, engine: HttpEngine, *, max_depth: int | None = None,
                 use_wordlist: bool = True, max_pages: int | None = None) -> None:
        self._engine = engine
        # Per-scan depth (ScanRequest.crawl_depth), never above the global cap.
        self._max_depth = min(max_depth or settings.MAX_CRAWL_DEPTH, settings.MAX_CRAWL_DEPTH)
        # Wordlist probes are active requests: never in passive mode.
        self._use_wordlist = use_wordlist and not engine.passive_only
        self._max_pages = max_pages or settings.MAX_CRAWL_PAGES
        self.off_host: set[str] = set()
        self._seen: set[tuple[str, str]] = set()  # (url, method)
        self._results: list[DiscoveredEndpoint] = []

    def _add(self, url: str, method: str, how: DiscoveryMethod,
             resp: HttpResult | None = None) -> bool:
        key = (_normalize(url), method.upper())
        if key in self._seen:
            return False
        if len(self._results) >= settings.MAX_ENDPOINTS:
            return False
        self._seen.add(key)
        ep = DiscoveredEndpoint(
            url=_normalize(url),
            path=urlparse(url).path or "/",
            method=method.upper(),
            discovered_by=how,
        )
        if resp is not None:
            ep.status_code = resp.status_code
            ep.content_type = resp.content_type
            ep.response_time = resp.response_time
        self._results.append(ep)
        return True

    async def crawl(self, seed_url: str) -> list[DiscoveredEndpoint]:
        """Run all four strategies starting from ``seed_url``."""
        seed = _normalize(seed_url)
        self._add(seed, "GET", DiscoveryMethod.SEED)

        # BFS queue of (url, depth) for strategies 1, 2, 4.
        queue: list[tuple[str, int]] = [(seed, 0)]
        visited: set[str] = set()

        while (queue and len(visited) < self._max_pages
               and len(self._results) < settings.MAX_ENDPOINTS):
            url, depth = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            resp = await self._engine.fetch(url)
            if not resp.ok:
                continue

            # Relative links resolve against where the page was served from.
            base = resp.final_url
            ctype = (resp.content_type or "").lower()
            if "html" in ctype:
                for link, method, how in self._extract_html(base, resp.body):
                    if not self._in_scope(seed, link, url):
                        continue
                    added = self._add(link, method, how)
                    # Follow GET links (pages and script sources) to the depth cap.
                    if added and depth < self._max_depth and method == "GET":
                        queue.append((_normalize(link), depth + 1))
            # Strategy 2: JS scan (inline scripts and fetched script files).
            if "javascript" in ctype or "html" in ctype:
                for link in self._extract_js(base, resp.body):
                    if self._in_scope(seed, link, url):
                        self._add(link, "GET", DiscoveryMethod.JAVASCRIPT)

        # Strategy 3: wordlist probing (bounded; ScanRequest.use_wordlist).
        if self._use_wordlist:
            await self._probe_wordlist(seed)

        logger.info("crawler discovered %d endpoints", len(self._results))
        return self._results

    def _in_scope(self, seed: str, link: str, found_on: str) -> bool:
        """Same origin as the seed; anything else is logged and never fetched."""
        if same_origin(seed, link):
            return True
        if urlparse(link).scheme in ("http", "https"):
            normalized = _normalize(link)
            if normalized not in self.off_host:
                self.off_host.add(normalized)
                logger.info("off-host link not followed: %s (found on %s)", normalized, found_on)
        return False

    def _extract_html(self, base: str, html: str
                      ) -> list[tuple[str, str, DiscoveryMethod]]:
        out: list[tuple[str, str, DiscoveryMethod]] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:  # noqa: BLE001 - malformed HTML must not crash
            return out
        for a in soup.find_all("a", href=True):
            out.append((urljoin(base, a["href"]), "GET", DiscoveryMethod.HTML))
        for form in soup.find_all("form"):
            action = form.get("action") or base
            method = (form.get("method") or "GET").upper()
            out.append((urljoin(base, action), method, DiscoveryMethod.HTML))
        for tag, attr in (("script", "src"), ("link", "href"), ("iframe", "src")):
            for el in soup.find_all(tag, **{attr: True}):
                out.append((urljoin(base, el[attr]), "GET", DiscoveryMethod.HTML))
        return out

    def _extract_js(self, base: str, text: str) -> list[str]:
        found: set[str] = set()
        for pattern in _JS_PATTERNS:
            for m in pattern.findall(text):
                if m.startswith(("http://", "https://", "/")):
                    found.add(urljoin(base, m))
        return list(found)

    async def _probe_wordlist(self, seed: str) -> None:
        root = f"{urlparse(seed).scheme}://{urlparse(seed).netloc}"
        # Soft-404 baseline: what a path that cannot exist returns.
        missing = await self._engine.fetch(f"{root}/cawasma-{secrets.token_hex(8)}",
                                           method="GET", same_origin_only=True)
        catch_all = missing.body if missing.ok and missing.status_code == 200 else None
        for path in PROBE_PATHS:
            if len(self._results) >= settings.MAX_ENDPOINTS:
                break
            url = root + path
            if (_normalize(url), "GET") in self._seen:
                continue
            resp = await self._engine.fetch(url, method="GET", same_origin_only=True)
            # Record only paths that exist: not 404/410, not a redirect we
            # stopped at, and not the site's catch-all page.
            if (resp.ok and resp.status_code not in (404, 410)
                    and not (300 <= (resp.status_code or 0) < 400)
                    and not (catch_all is not None and resp.body == catch_all)):
                self._add(url, "GET", DiscoveryMethod.WORDLIST, resp)
