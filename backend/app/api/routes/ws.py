"""WebSocket progress streaming (spec section 24).

``/ws/scans/{scan_id}`` sends a current snapshot from the database, then
forwards live progress events published by the worker to the scan's Redis
channel. Browsers that cannot use WebSockets can still poll ``GET
/api/scans/{id}/status``.
"""
from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.config import settings
from app.db.models import Scan
from app.db.models.enums import ScanStatus
from app.db.session import session_scope
from app.services.progress import channel_for
from app.utils.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["websocket"])

_TERMINAL = {ScanStatus.DONE, ScanStatus.FAILED}


async def _snapshot(scan_id: uuid.UUID) -> dict | None:
    async with session_scope() as session:
        scan = (await session.execute(
            select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        if scan is None:
            return None
        return {
            "type": "snapshot",
            "scan_id": str(scan.id),
            "status": scan.status.public_value,
            "percent": scan.progress,
            "stage": scan.current_stage,
            "terminal": scan.status in _TERMINAL,
        }


@router.websocket("/ws/scans/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        await websocket.send_text(json.dumps({"type": "error", "message": "invalid scan id"}))
        await websocket.close()
        return

    snap = await _snapshot(sid)
    if snap is None:
        await websocket.send_text(json.dumps({"type": "error", "message": "scan not found"}))
        await websocket.close()
        return

    await websocket.send_text(json.dumps(snap))
    if snap["terminal"]:
        await websocket.close()
        return

    redis = None
    pubsub = None
    try:
        import redis.asyncio as aioredis

        redis = aioredis.from_url(settings.REDIS_URL)
        pubsub = redis.pubsub()
        await pubsub.subscribe(channel_for(sid))
        # The scan may have finished between the snapshot and the subscribe;
        # its terminal event is then gone, so check once more.
        snap = await _snapshot(sid)
        if snap is not None and snap["terminal"]:
            await websocket.send_text(json.dumps(snap))
            return
        async for msg in pubsub.listen():
            if msg.get("type") != "message":
                continue
            data = msg["data"]
            text = data.decode() if isinstance(data, bytes) else str(data)
            await websocket.send_text(text)
            try:
                ev = json.loads(text)
                if (ev.get("percent", 0) >= 100
                        or ev.get("stage") in ("completed", "failed")):
                    break
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        logger.debug("ws client disconnected for scan %s", sid)
    except Exception as exc:  # noqa: BLE001 - never crash the socket handler
        logger.info("ws stream ended for %s: %s", sid, exc)
        try:
            await websocket.send_text(json.dumps(
                {"type": "error", "message": "progress stream unavailable; poll status"}))
        except Exception:  # noqa: BLE001
            pass
    finally:
        if pubsub is not None:
            try:
                await pubsub.unsubscribe(channel_for(sid))
                await pubsub.aclose()
            except Exception:  # noqa: BLE001
                pass
        if redis is not None:
            try:
                await redis.aclose()
            except Exception:  # noqa: BLE001
                pass
        try:
            await websocket.close()
        except Exception:  # noqa: BLE001
            pass
