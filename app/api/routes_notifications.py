"""Authenticated per-company WebSocket notifications."""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket
from starlette.websockets import WebSocketDisconnect

from app.database.database import SessionLocal
from app.database.models import User
from app.services.notifications import alert_connections
from app.services.security import SESSION_COOKIE, get_session_payload

router = APIRouter(tags=["notifications"])


@router.websocket("/ws/alerts")
async def company_alert_stream(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if not origin or urlparse(origin).netloc != websocket.headers.get("host"):
        await websocket.close(code=4403)
        return
    payload = get_session_payload(websocket.cookies.get(SESSION_COOKIE))
    if not payload:
        await websocket.close(code=4401)
        return

    database = SessionLocal()
    try:
        user = database.get(User, payload["user_id"])
        if (
            not user
            or user.status != "APPROVED"
            or payload.get("session_version") != user.session_version
        ):
            await websocket.close(code=4403)
            return
        company_id = user.company_id
        await websocket.accept()
        await alert_connections.add(company_id, user.id, websocket)
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                payload = get_session_payload(websocket.cookies.get(SESSION_COOKIE))
                user = database.query(User).populate_existing().filter(User.id == user.id).first()
                if (
                    not payload
                    or not user
                    or user.status != "APPROVED"
                    or user.company_id != company_id
                    or payload.get("session_version") != user.session_version
                ):
                    await websocket.close(code=4401)
                    return
                await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        return
    finally:
        if "user" in locals() and user:
            await alert_connections.remove(user.company_id, websocket)
        database.close()
