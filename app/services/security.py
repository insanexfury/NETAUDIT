"""Authentication, password hashing, scoped access, and audit helpers."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime
from threading import Lock
from typing import Any

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.config import COOKIE_SECURE, SESSION_SECRET
from app.database.database import get_db
from app.database.models import Analysis, AuditLog, User

SESSION_COOKIE = "netaudit_session"
GUEST_COOKIE = "netaudit_guest"
SESSION_SECONDS = 12 * 60 * 60
_signing_key = SESSION_SECRET.encode("utf-8") if SESSION_SECRET else secrets.token_bytes(32)
_rate_lock = Lock()
_rate_windows: dict[tuple[str, str], list[float]] = {}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=32768, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=64)
    return f"scrypt$32768$8$1${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = stored_hash.split("$")
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_unb64(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            maxmem=64 * 1024 * 1024,
            dklen=len(_unb64(expected)),
        )
        return hmac.compare_digest(actual, _unb64(expected))
    except (ValueError, TypeError):
        return False


def hash_joining_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def generate_joining_code() -> str:
    return secrets.token_urlsafe(32)


def new_session_cookie(response: Response, user: User) -> str:
    csrf_token = secrets.token_urlsafe(24)
    payload = {
        "user_id": user.id,
        "session_version": user.session_version,
        "expires": int(time.time()) + SESSION_SECONDS,
        "csrf": csrf_token,
    }
    response.set_cookie(
        SESSION_COOKIE,
        _encode_signed(payload),
        max_age=SESSION_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return csrf_token


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=COOKIE_SECURE, samesite="strict")


def create_guest_cookie() -> tuple[str, str]:
    guest_id = secrets.token_urlsafe(24)
    token = _encode_signed({"guest_id": guest_id, "expires": int(time.time()) + 24 * 60 * 60})
    return guest_id, token


def decode_guest_cookie(token: str | None) -> str | None:
    payload = _decode_signed(token)
    if not payload or payload.get("expires", 0) < int(time.time()):
        return None
    guest_id = payload.get("guest_id")
    return guest_id if isinstance(guest_id, str) else None


def get_session_payload(token: str | None) -> dict[str, Any] | None:
    payload = _decode_signed(token)
    if not payload or payload.get("expires", 0) < int(time.time()):
        return None
    if not isinstance(payload.get("user_id"), int) or not isinstance(payload.get("csrf"), str):
        return None
    return payload


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    payload = get_session_payload(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Your session has expired. Sign in again.")
    user = db.get(User, payload["user_id"])
    if (
        not user
        or user.status != "APPROVED"
        or payload.get("session_version") != user.session_version
    ):
        raise HTTPException(status_code=403, detail="This account is not permitted to access the workspace.")
    request.state.session_payload = payload
    return user


def get_current_user(user: User | None = Depends(get_optional_user)) -> User:
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in to access the company workspace.")
    return user


def require_roles(*roles: str):
    def role_dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Your role is not permitted to perform this action.")
        return user

    return role_dependency


def require_csrf(request: Request, user: User = Depends(get_current_user)) -> None:
    payload = getattr(request.state, "session_payload", None)
    if payload is None:
        payload = get_session_payload(request.cookies.get(SESSION_COOKIE))
    supplied = request.headers.get("x-csrf-token", "")
    if not payload or not hmac.compare_digest(supplied, payload["csrf"]):
        raise HTTPException(status_code=403, detail="The request could not be verified. Refresh the workspace and try again.")


def verify_csrf_for_authenticated_request(request: Request) -> None:
    """Require a session-bound token on mutations made with an authenticated cookie."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return
    payload = get_session_payload(token)
    supplied = request.headers.get("x-csrf-token", "")
    if not payload or not hmac.compare_digest(supplied, payload["csrf"]):
        raise HTTPException(status_code=403, detail="The request could not be verified. Refresh the workspace and try again.")


def get_analysis_for_user(analysis_id: int, user: User | None, request: Request, db: Session) -> Analysis:
    analysis = db.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if user:
        allowed = analysis.company_id == user.company_id
    else:
        allowed = analysis.company_id is None and analysis.guest_session_id == getattr(request.state, "guest_session_id", None)
    if not allowed:
        append_audit(
            db,
            "resource_access_denied",
            "denied",
            company_id=user.company_id if user else None,
            actor_user_id=user.id if user else None,
            resource_id=analysis_id,
        )
        db.commit()
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return analysis


def append_audit(
    db: Session,
    action: str,
    outcome: str,
    *,
    company_id: int | None = None,
    actor_user_id: int | None = None,
    resource_id: str | int | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    query = db.query(AuditLog)
    if company_id is None:
        query = query.filter(AuditLog.company_id.is_(None))
    else:
        query = query.filter(AuditLog.company_id == company_id)
    previous = query.order_by(AuditLog.id.desc()).first()
    previous_hash = previous.entry_hash if previous else "0" * 64
    event_time = datetime.utcnow()
    safe_details = details or {}
    canonical = json.dumps(
        {
            "action": action,
            "actor_user_id": actor_user_id,
            "company_id": company_id,
            "created_at": event_time.isoformat(),
            "details": safe_details,
            "outcome": outcome,
            "previous_hash": previous_hash,
            "resource_id": str(resource_id) if resource_id is not None else None,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    entry = AuditLog(
        company_id=company_id,
        actor_user_id=actor_user_id,
        action=action,
        outcome=outcome,
        resource_id=str(resource_id) if resource_id is not None else None,
        details_json=json.dumps(safe_details, sort_keys=True),
        created_at=event_time,
        previous_hash=previous_hash,
        entry_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    )
    db.add(entry)
    db.flush()
    return entry


def enforce_rate_limit(bucket: str, key: str, *, attempts: int = 10, period_seconds: int = 300) -> None:
    now = time.monotonic()
    marker = (bucket, key)
    with _rate_lock:
        history = [value for value in _rate_windows.get(marker, []) if now - value < period_seconds]
        if len(history) >= attempts:
            _rate_windows[marker] = history
            raise HTTPException(status_code=429, detail="Too many attempts. Please wait before trying again.")
        history.append(now)
        _rate_windows[marker] = history


def client_address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _encode_signed(payload: dict[str, Any]) -> str:
    content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(_signing_key, content, hashlib.sha256).digest()
    return f"{_b64(content)}.{_b64(signature)}"


def _decode_signed(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    try:
        content_text, signature_text = token.split(".", 1)
        content = _unb64(content_text)
        signature = _unb64(signature_text)
        expected = hmac.new(_signing_key, content, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(content)
        return payload if isinstance(payload, dict) else None
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
