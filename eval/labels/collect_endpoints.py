"""Collect bounded, same-origin endpoint paths from CAWASMA evaluation targets.

Sources, per target: its OpenAPI spec (where one is served), a same-origin HTML
crawl, and API paths referenced from JavaScript (inline scripts and bundles) --
Juice Shop and crAPI are single-page apps whose routes live only in their JS.
Static assets (scripts, styles, images, fonts) are fetched for scanning but
never written as endpoints: there is nothing to label on /main.js.

Two target-specific gaps are filled without logging in:

* crAPI's bundle holds routes as relative strings (``api/auth/login``) and the
  service prefix (``identity/``, ``workshop/``, ``community/``) separately, so
  each relative route is tried under each prefix found in the bundle and kept
  where the target does not answer 404;
* Juice Shop builds part of its URLs as ``this.host + "/suffix"``; each suffix
  is tried under the ``/rest/<service>`` bases already found;
* DVWA redirects everything to its login page, so its documented module paths
  (official README) are seeded and kept when they exist (any status but 404).

Every request is a plain GET to the isolated eval target.

The targets are only reachable inside the internal ``cawasma-eval`` network, so
run this through ``make eval-collect`` (the ``collector`` service), or point it
at another reachable host with ``--base-url NAME=URL``.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import secrets
import sys
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "eval" / "labels" / "endpoints_raw.csv"
TARGETS = {
    "juice-shop": "http://juice-shop:3000",
    "dvwa": "http://dvwa:80",
    "vampi": "http://vampi:5000",
    "crapi": "http://crapi-web:80",
}
OPENAPI_PATHS = ("/openapi.json", "/swagger.json", "/api-docs", "/openapi.yaml")
# Documented paths a logged-out crawl can't reach (DVWA README; Juice Shop's
# official challenge guide). They also seed the crawl: /ftp and friends are
# directory listings.
DOC_PATHS = {
    "juice-shop": [
        "/ftp", "/encryptionkeys", "/support/logs", "/api-docs", "/metrics",
        "/robots.txt", "/.well-known/security.txt", "/promotion", "/video", "/snippets",
        "/b2b/v2/orders", "/rest/memories", "/redirect",
    ],
    "dvwa": [
        "/login.php", "/logout.php", "/index.php", "/setup.php", "/security.php",
        "/phpinfo.php", "/about.php", "/instructions.php", "/robots.txt", "/config/",
        "/docs/", "/hackable/uploads/", "/external/",
        *(f"/vulnerabilities/{m}/" for m in (
            "brute", "exec", "csrf", "fi", "upload", "captcha", "sqli", "sqli_blind",
            "weak_id", "xss_d", "xss_r", "xss_s", "csp", "javascript", "authbypass",
            "open_redirect", "cryptography", "api", "view_source", "view_help")),
    ],
}
MAX_PAGES = 80
MAX_BODY = 8_000_000            # SPA bundles (Juice Shop main.js) are several MB
STATIC_EXT = (".js", ".mjs", ".map", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
              ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".webmanifest")
# Quoted absolute paths in JS that look like API routes: /api/..., /rest/...,
# /identity/api/..., /b2b/v2/..., /graphql (route ids like :id kept).
JS_API_PATH = re.compile(
    r"""["'`](/(?:[A-Za-z0-9_-]+/){0,2}(?:api|rest|b2b|graphql)(?:/[A-Za-z0-9_.:${}<>-]*)*)["'`]""")
JS_RELATIVE_API = re.compile(r"""["'`](api/[A-Za-z0-9_/.:${}<>-]+)["'`]""")
JS_PREFIX = re.compile(r"""["'`]([a-z][a-z0-9_-]{2,20}/)["'`]""")
JS_HOST_SUFFIX = re.compile(r"""host\s*\+\s*["'`](/[A-Za-z0-9_/-]+)["'`]""")
# Ids and placeholders all become ":id": 42, UUIDs, Mongo ids, {id}, :id, ${id}.
ID_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{4,}|[0-9a-f]{24}|\{[^}]*\}|:\w+|\$\{[^}]*\}|<[^>]*>)$",
    re.I)


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if key in {"href", "src", "action"} and value:
                self.links.add(value)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a 3xx answers "does it exist?"
        return None


_STATUS_OPENER = build_opener(_NoRedirect)


def exists(url: str) -> bool:
    """Whether a route exists, by one GET without following redirects.

    404 means no; so does a 5xx HTML error page (Juice Shop's answer to an
    unknown /rest or /api route). 2xx, 3xx, 401, 403, 405 and JSON errors: yes.
    """
    try:
        request = Request(url, headers={"User-Agent": "CAWASMA-eval-endpoint-collector"})
        with _STATUS_OPENER.open(request, timeout=8) as response:
            status, ctype = response.status, response.headers.get("Content-Type", "")
    except HTTPError as err:
        status, ctype = err.code, err.headers.get("Content-Type", "")
    except (OSError, URLError):
        return False
    return status != 404 and not (status >= 500 and "html" in ctype.lower())


def fetch(url: str) -> tuple[str, str, str] | None:
    """(body, content type, final URL after redirects), or None."""
    try:
        request = Request(url, headers={"User-Agent": "CAWASMA-eval-endpoint-collector"})
        with urlopen(request, timeout=8) as response:
            body = response.read(MAX_BODY)
            content_type = response.headers.get("Content-Type", "")
            return body.decode("utf-8", errors="replace"), content_type, response.geturl()
    except (OSError, URLError):
        return None


def normalize_path(path: str) -> str:
    parsed = urlparse(path)
    clean = parsed.path or "/"
    parts = [segment for segment in clean.rstrip(".").split("/") if segment]
    normalized = [":id" if ID_SEGMENT.fullmatch(segment) else segment for segment in parts]
    result = "/" + "/".join(normalized)
    return result if result != "/" else result


def add_openapi_paths(base: str, rows: set[tuple[str, str]]) -> None:
    for candidate in OPENAPI_PATHS:
        result = fetch(urljoin(base, candidate))
        if not result:
            continue
        body, content_type, final_url = result
        try:
            if candidate.endswith(".yaml") or "yaml" in content_type:
                import yaml  # optional: the collector container has no PyYAML
                document = yaml.safe_load(body)
            else:
                document = json.loads(body)
        except (ValueError, TypeError, ImportError):
            continue
        if isinstance(document, dict) and isinstance(document.get("paths"), dict):
            for path, operation_map in document["paths"].items():
                if isinstance(path, str) and isinstance(operation_map, dict):
                    for method in operation_map:
                        if method.lower() in {"get", "head", "options", "post", "put", "patch", "delete"}:
                            rows.add((method.upper(), normalize_path(path)))
            return


ID_IN_ROUTE = re.compile(r"<[^>]*>|\{[^}]*\}|\$\{[^}]*\}")


def is_static(path: str) -> bool:
    return urlparse(path).path.lower().endswith(STATIC_EXT)


def js_api_paths(text: str) -> set[str]:
    """API-looking absolute paths quoted in JavaScript."""
    return {normalize_path(m) for m in JS_API_PATH.findall(text) if "//" not in m}


def resolve_relative(base: str, relative: set[str], prefixes: set[str],
                     rows: set[tuple[str, str]]) -> None:
    """Keep each relative API route under the first prefix the target knows."""
    for route in sorted(relative):
        concrete = ID_IN_ROUTE.sub("1", route)          # <orderId> -> 1 for the request
        for prefix in ["", *sorted(prefixes)]:
            if exists(urljoin(base, "/" + prefix + concrete)):
                rows.add(("GET", normalize_path("/" + prefix + route)))
                break


def resolve_host_suffixes(base: str, suffixes: set[str], rows: set[tuple[str, str]]) -> None:
    """``host + "/suffix"`` pieces, tried under each /rest/<service> base found."""
    bases = sorted({"/".join(p.split("/")[:3]) for _, p in rows
                    if p.startswith("/rest/") and p.count("/") >= 2})
    # A base that accepts anything (/rest/track-order/:id) would "have" every
    # suffix: skip it.
    bases = [b for b in bases if not exists(urljoin(base, f"{b}/cawasma-{secrets.token_hex(6)}"))]
    for suffix in sorted(suffixes - {"/"}):
        for service in bases:
            if exists(urljoin(base, service + suffix)):
                rows.add(("GET", normalize_path(service + suffix)))


def add_doc_paths(target: str, base: str, rows: set[tuple[str, str]]) -> list[str]:
    """Record the documented paths that exist; return them as crawl seeds."""
    found = [urljoin(base, path) for path in DOC_PATHS.get(target, [])
             if exists(urljoin(base, path))]
    rows.update(("GET", normalize_path(url)) for url in found)
    return found


def crawl(base: str, rows: set[tuple[str, str]],
          relative: set[str] | None = None, prefixes: set[str] | None = None,
          suffixes: set[str] | None = None, seeds: tuple[str, ...] | list[str] = ()) -> None:
    origin = urlparse(base).netloc
    queue: deque[str] = deque([base, *seeds])
    seen: set[str] = set()
    while queue and len(seen) < MAX_PAGES:
        url = queue.popleft()
        parsed = urlparse(url)
        if parsed.netloc != origin or url in seen:
            continue
        seen.add(url)
        result = fetch(url)
        if not result:
            continue
        body, content_type, final_url = result
        ctype = content_type.lower()
        if not is_static(url):
            rows.add(("GET", normalize_path(url)))
        if "javascript" in ctype or "html" in ctype or url.endswith((".js", ".mjs")):
            rows.update(("GET", path) for path in js_api_paths(body))
            if relative is not None and prefixes is not None:
                relative.update(JS_RELATIVE_API.findall(body))
                prefixes.update(JS_PREFIX.findall(body))
            if suffixes is not None:
                suffixes.update(JS_HOST_SUFFIX.findall(body))
        if "html" not in ctype:
            continue
        parser = LinkParser()
        parser.feed(body)
        for link in parser.links:
            # Relative links resolve against the page we landed on, not the
            # URL we asked for (DVWA redirects /vulnerabilities/x/ to /login.php).
            child = urljoin(final_url, link)
            child_parsed = urlparse(child)
            if child_parsed.netloc == origin and child_parsed.scheme in {"http", "https"}:
                # Recorded only once fetched (above), so broken links don't count.
                # Scripts are fetched (for js_api_paths); other assets are not.
                if child not in seen and (not is_static(child)
                                          or child_parsed.path.endswith((".js", ".mjs"))):
                    queue.append(child)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*", help=f"subset of: {', '.join(TARGETS)}")
    parser.add_argument("--base-url", action="append", default=[], metavar="NAME=URL",
                        help="scan NAME at URL instead of the defaults (repeatable)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)

    if args.base_url:
        targets = dict(item.split("=", 1) for item in args.base_url if "=" in item)
        bad = [url for url in targets.values() if urlparse(url).scheme not in {"http", "https"}]
        if len(targets) != len(args.base_url) or bad:
            print("--base-url must be NAME=http(s)://host[:port]", file=sys.stderr)
            return 2
    else:
        unknown = sorted(set(args.targets) - set(TARGETS))
        if unknown:
            print(f"unknown target(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
        targets = {name: TARGETS[name] for name in args.targets} if args.targets else TARGETS

    output_rows: set[tuple[str, str, str]] = set()
    empty: list[str] = []
    for target, base in targets.items():
        rows: set[tuple[str, str]] = set()
        add_openapi_paths(base, rows)
        relative: set[str] = set()
        prefixes: set[str] = set()
        suffixes: set[str] = set()
        seeds = add_doc_paths(target, base, rows)
        crawl(base, rows, relative, prefixes, suffixes, seeds)
        resolve_relative(base, relative, prefixes, rows)
        resolve_host_suffixes(base, suffixes, rows)
        print(f"{target}: {len(rows)} endpoints from {base}", file=sys.stderr)
        if not rows:
            empty.append(target)
        output_rows.update((target, method, path) for method, path in rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["target", "method", "path"])
        writer.writerows(sorted(output_rows))
    print(f"wrote {len(output_rows)} endpoint rows to {args.output}")
    if empty:
        # An unreachable target must not look like a target with no endpoints.
        print(f"FAILED: no endpoints from {', '.join(empty)} (is it running and reachable?)",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
