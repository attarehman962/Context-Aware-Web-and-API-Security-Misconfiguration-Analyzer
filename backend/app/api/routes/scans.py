"""Scan REST endpoints (spec section 26)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas.scan import (
    ScanCreate,
    ScanCreated,
    ScanDetail,
    ScanResponse,
    ScanStatusResponse,
)
from app.db.session import get_session
from app.services import scan_service
from app.utils.validators import InvalidTargetError

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanCreated, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate, session: AsyncSession = Depends(get_session)
) -> ScanCreated:
    """Create a scan job. Returns immediately with a queued scan id."""
    # Same rule as POST /api/scan: no scan without the operator's confirmation.
    if not body.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="authorization_confirmed must be true: confirm you may test this target.",
        )
    try:
        scan = await scan_service.create_scan(
            session, body.target_url, authorization_confirmed=body.authorization_confirmed
        )
    except InvalidTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=exc.reason
        ) from None
    return ScanCreated(scan_id=scan.id, status=scan.status)


# GET /api/scans (history) is now served by the contract router (routes/contract.py).


async def _require_scan(session: AsyncSession, scan_id: uuid.UUID):
    scan = await scan_service.get_scan(session, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found."
        )
    return scan


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> ScanDetail:
    scan = await _require_scan(session, scan_id)
    summary = await scan_service.build_summary(session, scan_id)
    base = ScanResponse.model_validate(scan)
    return ScanDetail(**base.model_dump(), summary=summary)


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> ScanStatusResponse:
    scan = await _require_scan(session, scan_id)
    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress,
        current_stage=scan.current_stage,
    )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> Response:
    ok = await scan_service.delete_scan(session, scan_id)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found."
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
