"""Record what each evaluation target actually sends, as evidence for ground truth.

Passive only: one GET and one CORS preflight-style OPTIONS (with an Origin
header) per path, no bodies sent, no logins, and no path that changes state. Writes
``eval/ground_truth/observed/<target>.json`` with the status, the security
headers and the cookie *attributes* (never cookie values) of each path, so a
ground-truth entry can cite exactly what was seen and when.

Run on the eval network (the targets are not reachable from the host):

    make eval-up
    docker compose -f docker-compose.eval.yml run --rm collector \\
        python ground_truth/observe.py
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

OUT = Path(__file__).resolve().parent / "observed"
ORIGIN = "https://cawasma-probe.example"
HEADERS = (
    "server", "x-powered-by", "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
    "access-control-allow-origin", "access-control-allow-credentials",
    "ratelimit-limit", "x-ratelimit-limit", "content-type", "location",
)
# Paths from each project's documentation (README / challenge lists / OpenAPI).
TARGETS = {
    "juice-shop": ("http://juice-shop:3000", [
        "/", "/rest/products/search?q=", "/api/Products", "/api/Users", "/rest/user/login",
        "/ftp", "/ftp/acquisitions.md", "/api-docs", "/metrics", "/encryptionkeys",
        "/rest/admin/application-configuration", "/.well-known/security.txt",
    ]),
    "dvwa": ("http://dvwa:80", [
        "/", "/login.php", "/setup.php", "/config/", "/docs/", "/phpinfo.php",
        "/robots.txt", "/vulnerabilities/sqli/", "/.git/HEAD",
    ]),
    "vampi": ("http://vampi:5000", [
        "/", "/openapi.json", "/users/v1", "/users/v1/_debug", "/books/v1",
        "/users/v1/login",    # not /createdb: a GET there resets the database
    ]),
    "crapi": ("http://crapi-web:80", [
        "/", "/login", "/identity/api/auth/login", "/identity/api/v2/user/dashboard",
        "/community/api/v2/community/posts/recent", "/workshop/api/shop/products",
        "/identity/api/v2/vehicle/vehicles",
    ]),
}


# Checked on every target, for the INF-003/INF-004 true negatives.
for _base, _paths in TARGETS.values():
    _paths.extend(p for p in ("/.env", "/.git/HEAD", "/.git/config") if p not in _paths)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # record the 3xx itself
        return None


_OPENER = build_opener(_NoRedirect)


def _cookie_attrs(raw: str) -> dict[str, object]:
    name, _, rest = raw.partition("=")
    flags = [p.strip().lower() for p in rest.split(";")[1:]]
    samesite = next((f.split("=", 1)[1] for f in flags if f.startswith("samesite=")), None)
    return {"name": name.strip(), "httponly": "httponly" in flags, "secure": "secure" in flags,
            "samesite": samesite}


def probe(url: str, method: str) -> dict[str, object]:
    headers = {"User-Agent": "CAWASMA-eval-observer"}
    if method == "OPTIONS":
        headers |= {"Origin": ORIGIN, "Access-Control-Request-Method": "GET"}
    try:
        resp = _OPENER.open(Request(url, method=method, headers=headers), timeout=10)
    except HTTPError as err:          # 3xx/4xx/5xx still carry headers
        resp = err
    except (OSError, URLError) as exc:
        return {"error": str(exc)}
    with resp:
        body = resp.read(200_000).decode("utf-8", errors="replace") if method == "GET" else ""
        msg = resp.headers
        return {
            "status": resp.status,
            "headers": {h: msg.get(h) for h in HEADERS if msg.get(h) is not None},
            "cookies": [_cookie_attrs(c) for c in msg.get_all("Set-Cookie") or []],
            # Size only: bodies can hold the targets' (fake) user data.
            "body_bytes": len(body),
        }


def main() -> int:
    OUT.mkdir(exist_ok=True)
    failed = []
    for target, (base, paths) in TARGETS.items():
        record = {"target": target, "base_url": base,
                  "observed_at": datetime.now(UTC).isoformat(timespec="seconds"),
                  "paths": {p: {"GET": probe(base + p, "GET"),
                                "OPTIONS": probe(base + p, "OPTIONS")} for p in paths}}
        if all("error" in r["GET"] for r in record["paths"].values()):
            failed.append(target)
        (OUT / f"{target}.json").write_text(json.dumps(record, indent=2) + "\n")
        print(f"{target}: {len(paths)} paths -> {OUT / (target + '.json')}")
    if failed:
        print(f"FAILED: {', '.join(failed)} unreachable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
