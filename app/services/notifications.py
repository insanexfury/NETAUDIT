"""In-process, company-scoped WebSocket delivery for saved security alerts."""
from __future__ import annotations

import asyncio

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect

from app.database.database import SessionLocal
from app.database.models import User
from app.services.security import SESSION_COOKIE, get_session_payload


class AlertConnections:
    def __init__(self) -> None:
        self._by_company: dict[int, set[tuple[WebSocket, str]]] = {}
        self._lock = asyncio.Lock()

    async def add(self, company_id: int, user_id: int, websocket: WebSocket) -> None:
        async with self._lock:
            self._by_company.setdefault(company_id, set()).add((websocket, user_id))

    async def remove(self, company_id: int, websocket: WebSocket) -> None:
        async with self._lock:
            listeners = self._by_company.get(company_id, set())
            listeners.difference_update({item for item in listeners if item[0] is websocket})
            if not listeners:
                self._by_company.pop(company_id, None)

    async def publish(self, company_id: int, alert: dict) -> None:
        async with self._lock:
            listeners = tuple(self._by_company.get(company_id, set()))
        failed = []
        database = SessionLocal()
        try:
            for websocket, user_id in listeners:
                token = get_session_payload(websocket.cookies.get(SESSION_COOKIE))
                user = (
                    database.query(User).populate_existing().filter(User.id == user_id).first()
                    if token and token["user_id"] == user_id
                    else None
                )
                if (
                    not user
                    or user.status != "APPROVED"
                    or user.company_id != company_id
                    or token.get("session_version") != user.session_version
                ):
                    failed.append(websocket)
                    continue
                role = user.role
                payload = dict(alert)
                if role == "VIEWER/AUDITOR":
                    payload.pop("evidence", None)
                    payload.pop("description", None)
                try:
                    await websocket.send_json(payload)
                except (WebSocketDisconnect, OSError, RuntimeError):
                    failed.append(websocket)
        finally:
            database.close()
        for websocket in failed:
            await self.remove(company_id, websocket)


alert_connections = AlertConnections()


async def publish_alert(company_id: int, alert: dict) -> None:
    await alert_connections.publish(company_id, alert)
