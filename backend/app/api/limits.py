"""Per-client limits shared by the routes: scan creation and open SSE streams."""
from __future__ import annotations

from collections import Counter
from collections.abc import AsyncIterator

from fastapi import Request, status

from app.api.errors import ApiError
from app.config import settings
from app.services import rate_limit


def client_of(request: Request) -> str:
    return request.client.host if request.client else "?"


async def check_scan_rate_limit(request: Request) -> None:
    """429 RATE_LIMITED once the client has used its SCAN_RATE_LIMIT. Both scan
    routes call it, so the deprecated one is no way around the limit (SEC-03)."""
    decision = await rate_limit.limiter.hit(client_of(request))
    if not decision.allowed:
        raise ApiError(status.HTTP_429_TOO_MANY_REQUESTS, "RATE_LIMITED",
                       f"Too many scans: at most {decision.limit} per "
                       f"{settings.SCAN_RATE_LIMIT.split('/')[1]}. Try again in "
                       f"{decision.retry_after} s.",
                       headers={"Retry-After": str(decision.retry_after)})


# Open SSE streams per client in this process. Each stream polls the DB, so the
# cap keeps one client from loading it with many (SEC-09).
_open_streams: Counter[str] = Counter()


def open_stream(request: Request, events: AsyncIterator[str]) -> AsyncIterator[str]:
    """429 if the client is at the cap, else the stream, counted against its client
    from its first chunk until it ends or the client goes away. Counting inside
    the generator means a response that is never sent can't keep a slot."""
    client = client_of(request)
    if _open_streams[client] >= settings.SSE_MAX_STREAMS_PER_CLIENT:
        raise ApiError(status.HTTP_429_TOO_MANY_REQUESTS, "RATE_LIMITED",
                       f"Too many open live-status streams: at most "
                       f"{settings.SSE_MAX_STREAMS_PER_CLIENT} per client.")

    async def counted() -> AsyncIterator[str]:
        _open_streams[client] += 1
        try:
            async for chunk in events:
                yield chunk
        finally:
            _open_streams[client] -= 1
            if _open_streams[client] <= 0:
                del _open_streams[client]

    return counted()
