"""API contract v1 routes (docs/api-contract.md).

With ``MOCK_API=true`` every route here answers from :mod:`app.api.mock`
without touching the database or the scanner, so the frontend can be built
before the pipeline is finished.
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Response, status

from app.api import mock
from app.api.errors import ApiError
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
from app.db.session import SessionDep
from app.dependencies import PaginationParams, pagination
from app.services import contract_service, scan_service
from app.services.scan_runner import run_scan_async
from app.utils.security import SSRFError, validate_url_ssrf
from app.utils.validators import InvalidTargetError

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
    responses={202: _example(mock.QUEUED_STATUS), **_errors(400, 422)},
)
async def start_scan(body: ScanRequest, session: SessionDep, response: Response,
                     background: BackgroundTasks) -> ScanStatus:
    """Validate the target and queue a scan. Poll ``GET /api/results/{scan_id}``.

    ``authorisation_confirmed`` must be ``true`` (the schema rejects anything
    else with 422). The scan runs in this process as a background task for now
    (QUEUED -> RUNNING -> DONE | FAILED); the Celery worker takes over later.
    """
    if settings.MOCK_API:
        if not body.url.startswith("https://"):
            raise ApiError(400, "INVALID_TARGET", "Only https:// targets are allowed.")
        result = mock.QUEUED_STATUS.model_copy(update={"url": body.url})
    else:
        try:
            # Reject private/loopback/unresolvable targets now, not mid-scan. The
            # engine re-checks every request (DNS rebinding), so this is UX only.
            await asyncio.to_thread(validate_url_ssrf, body.url)
        except SSRFError as exc:
            raise ApiError(400, "INVALID_TARGET", str(exc)) from exc
        try:
            scan = await scan_service.create_scan(
                session, body.url, authorization_confirmed=body.authorisation_confirmed,
                options={**body.model_dump(include={"crawl_depth", "use_wordlist",
                                                     "passive_only"}),
                         "runner": "api"},       # see fail_interrupted_scans
                dispatch=False,
            )
        except InvalidTargetError as exc:
            raise ApiError(400, "INVALID_TARGET", exc.reason) from exc
        result = contract_service.scan_status(scan)
        if settings.AUTO_DISPATCH_SCANS:      # off in tests (no scan side effects)
            background.add_task(run_scan_async, scan.id)
    response.headers["Location"] = f"/api/results/{result.scan_id}"
    return result


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
