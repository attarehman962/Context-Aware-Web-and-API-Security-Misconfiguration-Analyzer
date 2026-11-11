"""Fixed-window rate limit for scan creation (``SCAN_RATE_LIMIT``, e.g. "5/minute").

Counted per client IP in Redis (``INCR`` + ``EXPIRE`` on one key per window),
so every api process shares the count. If Redis is unreachable it falls back to
a per-process counter rather than letting a Redis outage disable the limit, or
scanning altogether.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from app.config import settings
from app.utils.logging import get_logger

logger = get_logger(__name__)

_PERIODS = {"second": 1, "minute": 60, "hour": 3600}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int  # seconds until the window resets


def parse(rule: str) -> tuple[int, int] | None:
    """ "5/minute" -> (5, 60); empty -> None (no limit)."""
    if not rule.strip():
        return None
    count, _, period = rule.strip().partition("/")
    if not count.isdigit() or period not in _PERIODS or int(count) < 1:
        raise ValueError(f"SCAN_RATE_LIMIT must look like 5/minute, got {rule!r}")
    return int(count), _PERIODS[period]


class ScanRateLimiter:
    def __init__(self) -> None:
        """Set up the limiter with a local fallback counter."""
        self._local: dict[str, int] = {}
        self._redis: Any = None
        self._warned = False

    async def _incr_redis(self, key: str, window: int) -> int | None:
        """Increment the window counter in Redis, or None if down."""
        try:
            if self._redis is None:
                import redis.asyncio as aioredis

                self._redis = aioredis.from_url(
                    settings.REDIS_URL, socket_timeout=0.5, socket_connect_timeout=0.5
                )
            async with self._redis.pipeline(transaction=True) as pipe:
                count, _ = await pipe.incr(key).expire(key, window).execute()
            return int(count)
        except Exception as exc:  # noqa: BLE001 - fall back to the local counter
            if not self._warned:
                logger.warning("rate limit: Redis unavailable (%s); counting per process", exc)
                self._warned = True
            return None

    async def hit(self, client: str, now: float | None = None) -> Decision:
        """Record a request and decide whether it is allowed."""
        rule = parse(settings.SCAN_RATE_LIMIT)
        if rule is None:
            return Decision(True, 0, 0, 0)
        limit, window = rule
        now = time.time() if now is None else now
        bucket = int(now // window)
        key = f"cawasma:ratelimit:scan:{client}:{window}:{bucket}"
        count = await self._incr_redis(key, window)
        if count is None:
            self._local = {k: v for k, v in self._local.items() if k.endswith(f":{bucket}")}
            count = self._local[key] = self._local.get(key, 0) + 1
        retry_after = int(window - (now % window)) or 1
        return Decision(count <= limit, limit, max(limit - count, 0), retry_after)


limiter = ScanRateLimiter()
