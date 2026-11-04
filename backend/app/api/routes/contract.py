"""API contract v1 routes (docs/api-contract.md).

With ``MOCK_API=true`` every route here answers from :mod:`app.api.mock`
without touching the database or the scanner, so the frontend can be built
before the pipeline is finished.
"""
from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, Response, status
from fastapi.responses import StreamingResponse

from app.api import mock
from app.api.errors import ApiError
from app.api.limits import check_scan_rate_limit, open_stream
from app.api.schemas.common import ErrorResponse, Page, PaginationMeta
from app.api.schemas.contract import (
    ExportFormat,
    FindingDetail,
    ScanRequest,
    ScanResults,
    ScanStatus,
)
from app.config import settings
from app.core.reports import ReportFormatUnavailable
from app.db.models.enums import FindingCategory, Severity
from app.db.models.enums import ScanStatus as ScanState
from app.db.session import AsyncSessionLocal, SessionDep
from app.dependencies import PaginationParams, pagination
from app.services import contract_service, scan_dispatch, scan_runner, scan_service
from app.services.scan_runner import run_scan_async
from app.utils.security import SSRFError, validate_url_ssrf
from app.utils.validators import InvalidTargetError, validate_target_url

router = APIRouter(prefix="/api", tags=["contract v1"])


def _example(model: Any) -> dict[str, Any]:
    return {"content": {"application/json": {"example": model.model_dump(mode="json")}}}


def _errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    return {code: {"model": ErrorResponse} for code in codes}


def _not_found() -> ApiError:
    return ApiError(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Scan not found.")


@router.post(
    "/scan",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanStatus,
    summary="Start a scan",
    responses={202: _example(mock.QUEUED_STATUS), **_errors(400, 422, 429, 503)},
)
async def start_scan(body: ScanRequest, session: SessionDep, request: Request,
                     response: Response, background: BackgroundTasks) -> ScanStatus:
    """Validate the target and queue a scan on the Celery worker. Follow it with
    ``GET /api/scan/{scan_id}/events`` (SSE) or poll ``GET /api/results/{scan_id}``.

    ``authorisation_confirmed`` must be ``true`` (the schema rejects anything
    else with 422). Rate-limited per client (SCAN_RATE_LIMIT, 429 RATE_LIMITED).
    """
    await check_scan_rate_limit(request)
    if settings.MOCK_API:
        if not body.url.startswith("https://"):
            raise ApiError(400, "INVALID_TARGET", "Only https:// targets are allowed.")
        result = mock.QUEUED_STATUS.model_copy(update={"url": body.url})
    else:
        try:
            validate_target_url(body.url)
            # Reject private/loopback/unresolvable targets now, not mid-scan. The
            # engine re-checks every request (DNS rebinding), so this is UX only.
            await asyncio.to_thread(validate_url_ssrf, body.url)
        except InvalidTargetError as exc:
            raise ApiError(400, "INVALID_TARGET", exc.reason) from exc
        except SSRFError as exc:
            raise ApiError(400, "INVALID_TARGET", str(exc)) from exc
        try:
            scan = await scan_service.create_scan(
                session, body.url, authorization_confirmed=body.authorisation_confirmed,
                options={**body.model_dump(include={"crawl_depth", "use_wordlist",
                                                     "passive_only"}),
                         # "api" scans die with this process: see fail_interrupted_scans
                         "runner": "api" if settings.RUN_SCANS_INLINE else "celery"},
                dispatch=False,
            )
        except InvalidTargetError as exc:
            raise ApiError(400, "INVALID_TARGET", exc.reason) from exc
        if settings.RUN_SCANS_INLINE:
            background.add_task(run_scan_async, scan.id)
        elif settings.AUTO_DISPATCH_SCANS:      # off in tests (no broker)
            try:
                await asyncio.to_thread(scan_dispatch.queue_scan, scan.id)
            except scan_dispatch.QueueUnavailable as exc:
                await scan_service.mark_failed(session, scan, "Could not queue the scan: "
                                                              "the scan worker is unavailable.")
                raise ApiError(status.HTTP_503_SERVICE_UNAVAILABLE, "QUEUE_UNAVAILABLE",
                               "The scan queue is unavailable; try again shortly.") from exc
        result = contract_service.scan_status(scan)
    response.headers["Location"] = f"/api/results/{result.scan_id}"
    return result


@router.post(
    "/scan/{scan_id}/cancel",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanStatus,
    summary="Cancel a queued or running scan",
    responses={**_errors(404, 409, 422)},
)
async def cancel_scan(scan_id: uuid.UUID, session: SessionDep) -> ScanStatus:
    """Since 1.3. A QUEUED scan becomes FAILED ("Cancelled by the user.") at once;
    a RUNNING one stops at its next progress step and ends the same way (follow
    it on the events stream). 409 SCAN_FINISHED for a DONE or FAILED scan."""
    if settings.MOCK_API:
        found = mock.RESULTS.get(scan_id)
        if found is None:
            raise _not_found()
        current = found.scan
        if current.status in (ScanState.DONE, ScanState.FAILED):
            raise ApiError(status.HTTP_409_CONFLICT, "SCAN_FINISHED",
                           f"Scan is already {current.status.value}.")
        return current.model_copy(update={"status": ScanState.FAILED,
                                          "error": scan_runner.CANCELLED})
    scan = await scan_service.get_scan(session, scan_id)
    if scan is None:
        raise _not_found()
    if scan.status in (ScanState.DONE, ScanState.FAILED):
        raise ApiError(status.HTTP_409_CONFLICT, "SCAN_FINISHED",
                       f"Scan is already {scan.status.value}.")
    await scan_service.request_cancel(session, scan)
    await asyncio.to_thread(scan_dispatch.revoke_scan, scan.id)
    return contract_service.scan_status(scan)


@router.get(
    "/scan/{scan_id}/events",
    summary="Live status (Server-Sent Events)",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}},
                     "description": "`event: status` with a ScanStatus JSON each time it "
                                    "changes; ends after DONE or FAILED."},
               **_errors(404, 422, 429)},
)
async def scan_events(scan_id: uuid.UUID, request: Request) -> StreamingResponse:
    """Since 1.3. One ``status`` event now, then one per change (progress, stage,
    counts, status); a comment line every 15 s keeps proxies from closing it. The
    stream ends after the DONE or FAILED event; then GET /api/results has the
    findings. EventSource reconnects by itself (``retry: 3000``)."""
    if settings.MOCK_API:
        found = mock.RESULTS.get(scan_id)
        if found is None:
            raise _not_found()
        return _sse(_mock_events(found.scan))
    async with AsyncSessionLocal() as session:
        if await scan_service.get_scan(session, scan_id) is None:
            raise _not_found()
    return _sse(open_stream(request, _events(scan_id, request)))


def _sse(events: AsyncIterator[str]) -> StreamingResponse:
    return StreamingResponse(events, media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _event(status_: ScanStatus) -> str:
    return f"event: status\ndata: {status_.model_dump_json()}\n\n"


async def _mock_events(current: ScanStatus) -> AsyncIterator[str]:
    yield "retry: 3000\n\n" + _event(current)      # mock scans don't move: one event


async def _events(scan_id: uuid.UUID, request: Request) -> AsyncIterator[str]:
    """Re-read the scan every SSE_POLL_SECONDS, from its own short session each
    time, so it sees the worker's commits; emit when anything shown changes."""
    yield "retry: 3000\n\n"
    last, idle = None, 0.0
    while True:
        async with AsyncSessionLocal() as session:
            scan = await scan_service.get_scan(session, scan_id)
            current = contract_service.scan_status(scan) if scan is not None else None
        if current is None:
            return
        shown = current.model_dump_json(exclude={"severity_counts"})
        if shown != last:
            last, idle = shown, 0.0
            yield _event(current)
        if current.status in (ScanState.DONE, ScanState.FAILED) or \
                await request.is_disconnected():
            return
        await asyncio.sleep(settings.SSE_POLL_SECONDS)
        idle += settings.SSE_POLL_SECONDS
        if idle >= 15:
            idle = 0.0
            yield ": keep-alive\n\n"


@router.get(
    "/results/{scan_id}",
    response_model=ScanResults,
    summary="Scan status and results",
    responses={200: _example(mock.RESULTS[mock.DONE_ID]), **_errors(404, 422)},
)
async def get_results(
    scan_id: uuid.UUID, session: SessionDep,
    severity: list[Severity] | None = Query(
        None, description="Since 1.2. Keep these severity buckets (repeat the parameter)."),
    category: list[FindingCategory] | None = Query(
        None, description="Since 1.2. Keep these categories (repeat the parameter)."),
    owasp: list[str] | None = Query(
        None, description="Since 1.2. Keep findings mapped to any of these OWASP ids, "
                          "e.g. A05:2021 or API8:2023 (case-insensitive)."),
    in_chain: bool | None = Query(
        None, description="Since 1.2. true: only attack-chain members; false: only others."),
    page: int | None = Query(None, ge=1, description="Since 1.2. Paginate findings."),
    limit: int | None = Query(None, ge=1, le=500,
                              description="Since 1.2. Findings per page (default 50)."),
) -> ScanResults:
    """Always 200 for a known scan. ``findings`` and ``chains`` stay empty until
    ``scan.status`` is ``DONE``. Filters combine with AND (values of one filter
    with OR); ``severity_counts`` and ``chains`` always cover the whole scan, and
    ``findings_meta.total`` counts the filtered findings."""
    if settings.MOCK_API:
        if scan_id not in mock.RESULTS:
            raise _not_found()
        results = mock.RESULTS[scan_id]
    else:
        found = await contract_service.get_results(session, scan_id)
        if found is None:
            raise _not_found()
        results = found
    flt = contract_service.FindingFilter(
        severity=frozenset(severity or ()), category=frozenset(category or ()),
        owasp=frozenset(owasp or ()), in_chain=in_chain)
    return contract_service.select_findings(results, flt, page, limit)


@router.get(
    "/results/{scan_id}/findings/{finding_id}",
    response_model=FindingDetail,
    summary="One finding with its endpoint, score breakdown and chains",
    responses={200: _example(mock.finding_detail(mock.DONE_ID, mock.CHAIN_MEMBER_ID)),
               **_errors(404, 422)},
)
async def get_finding(scan_id: uuid.UUID, finding_id: uuid.UUID,
                      session: SessionDep) -> FindingDetail:
    """Since 1.2. 404 when the scan or the finding (in that scan) doesn't exist."""
    if settings.MOCK_API:
        detail = mock.finding_detail(scan_id, finding_id)
    else:
        detail = await contract_service.get_finding_detail(session, scan_id, finding_id)
    if detail is None:
        raise ApiError(status.HTTP_404_NOT_FOUND, "NOT_FOUND", "Finding not found.")
    return detail


@router.get(
    "/results/{scan_id}/export",
    summary="Download results as JSON, CSV, HTML or PDF",
    response_class=Response,
    responses={
        200: {"content": {t: {} for t in contract_service.MEDIA_TYPES.values()},
              "description": "File download (Content-Disposition: attachment)."},
        **_errors(404, 409, 422, 501),
    },
)
async def export_results(
    scan_id: uuid.UUID, session: SessionDep,
    format: ExportFormat = Query("json", description="json | csv | html | pdf"),  # noqa: A002
) -> Response:
    if settings.MOCK_API:
        results = mock.RESULTS.get(scan_id)
    else:
        results = await contract_service.get_results(session, scan_id)
    if results is None:
        raise _not_found()
    if results.scan.status != ScanState.DONE:
        raise ApiError(status.HTTP_409_CONFLICT, "SCAN_NOT_FINISHED",
                       f"Scan is {results.scan.status.value}; export is available when DONE.")
    try:
        content = contract_service.export(results, format)
    except ReportFormatUnavailable as exc:
        raise ApiError(status.HTTP_501_NOT_IMPLEMENTED, "FORMAT_UNAVAILABLE", str(exc)) from exc
    return Response(
        content=content,
        media_type=contract_service.MEDIA_TYPES[format],
        headers={"Content-Disposition": f'attachment; filename="cawasma-{scan_id}.{format}"'},
    )


@router.get(
    "/scans",
    response_model=Page[ScanStatus],
    summary="Scan history, newest first",
    responses={200: {"content": {"application/json": {"example": {
        "items": [s.model_dump(mode="json") for s in mock.SCANS],
        "meta": {"page": 1, "limit": 20, "total": len(mock.SCANS), "pages": 1},
    }}}}, **_errors(422)},
)
async def list_scans(
    session: SessionDep, page: PaginationParams = Depends(pagination),
) -> Page[ScanStatus]:
    if settings.MOCK_API:
        items, total = mock.SCANS[page.offset:page.offset + page.limit], len(mock.SCANS)
    else:
        items, total = await contract_service.list_scans(session, page.offset, page.limit)
    return Page[ScanStatus](items=items, meta=PaginationMeta(
        page=page.page, limit=page.limit, total=total,
        pages=(total + page.limit - 1) // page.limit,
    ))
