"""Company-scoped administration, policy management, and audit history."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Analysis, AuditLog, Company, DetectionSettings, User
from app.services.detection_settings import DetectionPolicy
from app.services.security import (
    append_audit,
    generate_joining_code,
    get_current_user,
    hash_joining_code,
    require_csrf,
    require_roles,
)

router = APIRouter(prefix="/company", tags=["company"])


class RequestDecision(BaseModel):
    status: Literal["APPROVED", "REJECTED"]
    role: Literal["ADMIN", "SECURITY_ANALYST", "VIEWER/AUDITOR"] | None = None


class RoleChange(BaseModel):
    role: Literal["ADMIN", "SECURITY_ANALYST", "VIEWER/AUDITOR"]


def _company(db: Session, company_id: int) -> Company:
    company = db.get(Company, company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Company workspace not found.")
    return company


def _company_user(db: Session, user_id: int, company_id: int) -> User:
    user = db.query(User).filter(User.id == user_id, User.company_id == company_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Company user not found.")
    return user


def _prevent_last_admin_change(db: Session, target: User, new_role: str | None = None, new_status: str | None = None) -> None:
    removes_admin = target.role == "ADMIN" and (
        new_role is not None and new_role != "ADMIN"
        or new_status is not None and new_status != "APPROVED"
    )
    if removes_admin:
        active_admins = db.query(User.id).filter(
            User.company_id == target.company_id,
            User.role == "ADMIN",
            User.status == "APPROVED",
        ).count()
        if active_admins <= 1:
            raise HTTPException(status_code=409, detail="The company must retain at least one approved administrator.")


@router.get("/overview")
def company_overview(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    company = _company(db, user.company_id)
    return {
        "company": {"id": company.id, "name": company.name},
        "user": {"id": user.id, "full_name": user.full_name, "role": user.role},
        "analysis_count": db.query(Analysis.id).filter(Analysis.company_id == company.id).count(),
        "pending_requests": db.query(User.id).filter(
            User.company_id == company.id, User.status == "PENDING"
        ).count(),
    }


@router.get("/users")
def company_users(
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
):
    rows = db.query(User).filter(User.company_id == user.company_id).order_by(User.created_at.desc()).all()
    return [
        {
            "id": item.id,
            "full_name": item.full_name,
            "username": item.username,
            "email": item.email,
            "role": item.role,
            "status": item.status,
            "created_at": item.created_at.isoformat(),
        }
        for item in rows
    ]


@router.post("/requests/{user_id}/decision")
def decide_access_request(
    user_id: int,
    payload: RequestDecision,
    user: User = Depends(require_roles("ADMIN")),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    applicant = _company_user(db, user_id, user.company_id)
    if payload.status == "APPROVED":
        if payload.role is None:
            raise HTTPException(status_code=422, detail="Choose the final role before approving this request.")
        final_role = payload.role
    else:
        final_role = applicant.role
    result = db.query(User).filter(
        User.id == applicant.id,
        User.company_id == user.company_id,
        User.status == "PENDING",
    ).update(
        {"status": payload.status, "role": final_role},
        synchronize_session=False,
    )
    if result != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="This access request has already been reviewed.")
    db.refresh(applicant)
    append_audit(
        db,
        "access_request_" + payload.status.lower(),
        "success",
        company_id=user.company_id,
        actor_user_id=user.id,
        resource_id=applicant.id,
        details={"assigned_role": applicant.role if payload.status == "APPROVED" else None},
    )
    db.commit()
    return {"id": applicant.id, "status": applicant.status, "role": applicant.role}


@router.patch("/users/{user_id}/role")
def change_user_role(
    user_id: int,
    payload: RoleChange,
    user: User = Depends(require_roles("ADMIN")),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    target = _company_user(db, user_id, user.company_id)
    if target.status != "APPROVED":
        raise HTTPException(status_code=409, detail="Only approved users can have their role changed.")
    old_role = target.role
    _prevent_last_admin_change(db, target, new_role=payload.role)
    target.role = payload.role
    append_audit(
        db,
        "user_role_changed",
        "success",
        company_id=user.company_id,
        actor_user_id=user.id,
        resource_id=target.id,
        details={"old_role": old_role, "new_role": payload.role},
    )
    db.commit()
    return {"id": target.id, "role": target.role}


@router.post("/users/{user_id}/suspend")
def suspend_user(
    user_id: int,
    user: User = Depends(require_roles("ADMIN")),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    target = _company_user(db, user_id, user.company_id)
    if target.status == "SUSPENDED":
        return {"id": target.id, "status": target.status}
    if target.status != "APPROVED":
        raise HTTPException(status_code=409, detail="Only approved company users can be suspended.")
    _prevent_last_admin_change(db, target, new_status="SUSPENDED")
    target.status = "SUSPENDED"
    append_audit(
        db,
        "user_suspended",
        "success",
        company_id=user.company_id,
        actor_user_id=user.id,
        resource_id=target.id,
    )
    db.commit()
    return {"id": target.id, "status": target.status}


@router.post("/joining-code/rotate")
def rotate_joining_code(
    user: User = Depends(require_roles("ADMIN")),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    company = _company(db, user.company_id)
    code = generate_joining_code()
    company.joining_code_hash = hash_joining_code(code)
    append_audit(
        db,
        "joining_code_rotated",
        "success",
        company_id=company.id,
        actor_user_id=user.id,
        resource_id=company.id,
    )
    db.commit()
    return {"joining_code": code}


@router.get("/settings")
def get_detection_settings(
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
):
    settings = db.get(DetectionSettings, user.company_id)
    if not settings:
        raise HTTPException(status_code=503, detail="Company detection settings are unavailable.")
    return {"version": settings.version, "settings": json.loads(settings.settings_json), "updated_at": settings.updated_at.isoformat()}


@router.put("/settings")
def update_detection_settings(
    payload: DetectionPolicy,
    user: User = Depends(require_roles("ADMIN")),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    if payload.model_fields_set != set(DetectionPolicy.model_fields):
        raise HTTPException(status_code=422, detail="Provide every detection setting; partial policy updates are not accepted.")
    settings = db.get(DetectionSettings, user.company_id)
    if not settings:
        raise HTTPException(status_code=503, detail="Company detection settings are unavailable.")
    new_values = payload.model_dump()
    old_values = json.loads(settings.settings_json)
    settings.settings_json = json.dumps(new_values, sort_keys=True)
    settings.version += 1
    settings.updated_by_id = user.id
    settings.updated_at = datetime.utcnow()
    append_audit(
        db,
        "detection_settings_changed",
        "success",
        company_id=user.company_id,
        actor_user_id=user.id,
        resource_id=settings.version,
        details={"old": old_values, "new": new_values, "version": settings.version},
    )
    db.commit()
    return {"version": settings.version, "settings": new_values}


@router.get("/audit")
def company_audit_log(
    user: User = Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
):
    entries = db.query(AuditLog).filter(AuditLog.company_id == user.company_id).order_by(AuditLog.id).all()
    previous_hash = "0" * 64
    verified = True
    for entry in entries:
        if entry.previous_hash != previous_hash:
            verified = False
            break
        canonical = json.dumps(
            {
                "action": entry.action,
                "actor_user_id": entry.actor_user_id,
                "company_id": entry.company_id,
                "created_at": entry.created_at.isoformat(),
                "details": json.loads(entry.details_json),
                "outcome": entry.outcome,
                "previous_hash": entry.previous_hash,
                "resource_id": entry.resource_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != entry.entry_hash:
            verified = False
            break
        previous_hash = entry.entry_hash
    recent = entries[-200:]
    return {
        "chain_valid": verified,
        "entries": [
            {
                "id": item.id,
                "actor_user_id": item.actor_user_id,
                "action": item.action,
                "outcome": item.outcome,
                "resource_id": item.resource_id,
                "details": json.loads(item.details_json),
                "created_at": item.created_at.isoformat(),
                "entry_hash": item.entry_hash,
            }
            for item in reversed(recent)
        ],
    }
