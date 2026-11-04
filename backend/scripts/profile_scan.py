"""Profile one scan: seconds per stage and requests sent (Atta Prompt 10).

Runs the real pipeline (no database) against ``URL`` and prints JSON with
``stats["stage_seconds"]``, the request count and the endpoint/finding counts.
Use it where the target is reachable, e.g. on the eval network:

    docker compose -f docker-compose.yml -f docker-compose.eval-scan.yml \\
        run --rm --no-deps api python -m scripts.profile_scan https://juice-shop-tls/

Options mirror the eval harness (crawl depth 2, wordlist on, active probes).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time

from app.core.pipeline import run_pipeline


async def profile(url: str, *, passive: bool, repeat: int) -> dict:
    runs = []
    for _ in range(repeat):
        start = time.perf_counter()
        result = await run_pipeline(url, probe=not passive, passive_only=passive,
                                    crawl_depth=2, use_wordlist=True)
        runs.append({"wall_seconds": round(time.perf_counter() - start, 2),
                     "stage_seconds": result.stats["stage_seconds"],
                     "requests": result.stats["requests"],
                     "endpoints": result.stats["endpoints"],
                     "findings": result.stats["findings"]})
    return {"url": url, "passive": passive, "runs": runs}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("urls", nargs="+")
    p.add_argument("--passive", action="store_true")
    p.add_argument("--repeat", type=int, default=1)
    args = p.parse_args(argv)
    for url in args.urls:
        print(json.dumps(asyncio.run(profile(url, passive=args.passive, repeat=args.repeat))),
              flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
