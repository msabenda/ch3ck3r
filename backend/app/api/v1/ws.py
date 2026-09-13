"""WebSocket handler for real-time scan progress streaming."""

import asyncio
import json
import logging
from datetime import datetime
from uuid import UUID

from fastapi import WebSocket, WebSocketDisconnect, APIRouter, Depends
from sqlalchemy import select

from app.db.session import get_db
from app.models import Scan, ScanStatus, Finding
from app.core.security import get_current_user_ws

logger = logging.getLogger(__name__)

router = APIRouter()


class ScanProgressManager:
    """Manages WebSocket connections for real-time scan progress."""

    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}  # scan_id -> [websockets]
        self._user_connections: dict[str, list[tuple[str, WebSocket]]] = {}  # user_id -> [(scan_id, ws)]

    async def connect(self, websocket: WebSocket, scan_id: str, user_id: str):
        await websocket.accept()
        if scan_id not in self._connections:
            self._connections[scan_id] = []
        self._connections[scan_id].append(websocket)

        if user_id not in self._user_connections:
            self._user_connections[user_id] = []
        self._user_connections[user_id].append((scan_id, websocket))

        # Send initial status
        await self.send_update(scan_id, {
            "type": "connected",
            "scan_id": scan_id,
            "message": "Monitoring scan progress",
        })

    async def disconnect(self, websocket: WebSocket, scan_id: str, user_id: str):
        if scan_id in self._connections:
            if websocket in self._connections[scan_id]:
                self._connections[scan_id].remove(websocket)
            if not self._connections[scan_id]:
                del self._connections[scan_id]

        if user_id in self._user_connections:
            self._user_connections[user_id] = [
                (sid, ws) for sid, ws in self._user_connections[user_id]
                if not (sid == scan_id and ws == websocket)
            ]
            if not self._user_connections[user_id]:
                del self._user_connections[user_id]

    async def send_update(self, scan_id: str, data: dict):
        """Send update to all connections watching a scan."""
        if scan_id not in self._connections:
            return
        message = json.dumps(data, default=str)
        stale = []
        for ws in self._connections[scan_id]:
            try:
                await ws.send_text(message)
            except Exception:
                stale.append(ws)
        for ws in stale:
            if scan_id in self._connections and ws in self._connections[scan_id]:
                self._connections[scan_id].remove(ws)

    async def broadcast_scan_event(self, scan: Scan, event_type: str, extra: dict = None):
        """Broadcast a scan lifecycle event to all watchers."""
        data = {
            "type": event_type,
            "scan_id": str(scan.id),
            "project_id": str(scan.project_id),
            "scan_type": scan.scan_type,
            "target": scan.target,
            "status": scan.status.value,
            "risk_score": scan.risk_score,
            "total_findings": scan.total_findings,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
            "info_count": scan.info_count,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if extra:
            data.update(extra)
        await self.send_update(str(scan.id), data)

    async def broadcast_finding(self, scan_id: str, finding: dict):
        """Broadcast a new finding in real-time."""
        await self.send_update(scan_id, {
            "type": "finding",
            "scan_id": scan_id,
            "finding": finding,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def close_all(self):
        """Close all connections (on shutdown)."""
        for scan_id, connections in self._connections.items():
            for ws in connections:
                try:
                    await ws.close()
                except Exception:
                    pass
        self._connections.clear()
        self._user_connections.clear()


# Global progress manager
progress_manager = ScanProgressManager()


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_websocket(
    websocket: WebSocket,
    scan_id: str,
    token: str = None,
    db=Depends(get_db),
):
    """WebSocket endpoint for real-time scan progress.

    Connect with: ws://host/ws/scans/{scan_id}?token={jwt_token}
    """
    # Validate token and scan access
    user = None
    try:
        user = await get_current_user_ws(token)
    except Exception:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    try:
        result = await db.execute(select(Scan).where(Scan.id == UUID(scan_id)))
        scan = result.scalar_one_or_none()
        if not scan:
            await websocket.close(code=4004, reason="Scan not found")
            return
    except Exception:
        await websocket.close(code=4000, reason="Invalid scan ID")
        return

    user_id = str(user.sub) if hasattr(user, 'sub') else str(user.id)

    await progress_manager.connect(websocket, scan_id, user_id)
    logger.info(f"WebSocket connected: user={user_id} scan={scan_id}")

    try:
        while True:
            # Keep connection alive — client can send pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: user={user_id} scan={scan_id}")
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        await progress_manager.disconnect(websocket, scan_id, user_id)
