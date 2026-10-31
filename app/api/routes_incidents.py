"""Company-scoped incident cases with auditable status and investigation events."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Alert, Analysis, Incident, IncidentAnalysis, IncidentEvent, User
from app.services.security import append_audit, get_current_user, require_csrf, require_roles

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentCreate(BaseModel):
    title: str = Field(min_length=4, max_length=200)
    analysis_id: int | None = None
    analysis_ids: list[int] = Field(default_factory=list, max_length=20)
    alert_id: int | None = None
    assigned_to_id: int | None = None


class IncidentUpdate(BaseModel):
    status: Literal["NEW", "UNDER_INVESTIGATION", "ESCALATED", "RESOLVED"] | None = None
    assigned_to_id: int | None = None


class IncidentNote(BaseModel):
    note: str = Field(min_length=1, max_length=4000)


def _incident(db: Session, incident_id: int, company_id: int) -> Incident:
    incident = db.query(Incident).filter(
        Incident.id == incident_id,
        Incident.company_id == company_id,
    ).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident


def _assigned_analyst(db: Session, user_id: int | None, company_id: int) -> User | None:
    if user_id is None:
        return None
    assigned = db.query(User).filter(
        User.id == user_id,
        User.company_id == company_id,
        User.role == "SECURITY_ANALYST",
        User.status == "APPROVED",
    ).first()
    if not assigned:
        raise HTTPException(status_code=422, detail="Choose an approved Security Analyst from your company.")
    return assigned


def _serialize_event(event: IncidentEvent) -> dict:
    return {
        "id": event.id,
        "actor_user_id": event.actor_user_id,
        "event_type": event.event_type,
        "details": event.details,
        "created_at": event.created_at.isoformat(),
    }


@router.get("")
def list_incidents(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    incidents = db.query(Incident).filter(Incident.company_id == user.company_id).order_by(Incident.updated_at.desc()).all()
    return [
        {
            "id": incident.id,
            "title": incident.title,
            "status": incident.status,
            "severity": incident.severity,
            "analysis_id": incident.analysis_id,
            "analysis_ids": [
                row.analysis_id for row in db.query(IncidentAnalysis).filter(IncidentAnalysis.incident_id == incident.id).all()
            ],
            "alert_id": incident.alert_id,
            "assigned_to_id": incident.assigned_to_id,
            "created_at": incident.created_at.isoformat(),
            "updated_at": incident.updated_at.isoformat(),
        }
        for incident in incidents
    ]


@router.get("/{incident_id}")
def get_incident(incident_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    incident = _incident(db, incident_id, user.company_id)
    events = db.query(IncidentEvent).filter(
        IncidentEvent.incident_id == incident.id,
    ).order_by(IncidentEvent.id).all()
    return {
        "id": incident.id,
        "title": incident.title,
        "status": incident.status,
        "severity": incident.severity,
        "analysis_id": incident.analysis_id,
        "analysis_ids": [
            row.analysis_id for row in db.query(IncidentAnalysis).filter(IncidentAnalysis.incident_id == incident.id).all()
        ],
        "alert_id": incident.alert_id,
        "assigned_to_id": incident.assigned_to_id,
        "events": [_serialize_event(event) for event in events],
    }


@router.post("", status_code=201)
def create_incident(
    payload: IncidentCreate,
    request: Request,
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    analysis = None
    alert = None
    if payload.alert_id is not None:
        alert = (
            db.query(Alert)
            .join(Analysis, Alert.analysis_id == Analysis.id)
            .filter(Alert.id == payload.alert_id, Analysis.company_id == user.company_id)
            .first()
        )
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found.")
        if payload.analysis_id is not None and payload.analysis_id != alert.analysis_id:
            raise HTTPException(status_code=422, detail="The alert does not belong to the selected analysis.")
        analysis = db.get(Analysis, alert.analysis_id)
    elif payload.analysis_id is not None:
        analysis = db.query(Analysis).filter(
            Analysis.id == payload.analysis_id,
            Analysis.company_id == user.company_id,
        ).first()
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found.")
    analysis_ids = set(payload.analysis_ids)
    if analysis:
        analysis_ids.add(analysis.id)
    if payload.analysis_ids:
        authorized_ids = {
            row.id for row in db.query(Analysis.id).filter(
                Analysis.id.in_(analysis_ids),
                Analysis.company_id == user.company_id,
            ).all()
        }
        if authorized_ids != analysis_ids:
            raise HTTPException(status_code=404, detail="One or more analyses were not found.")
    assigned = _assigned_analyst(db, payload.assigned_to_id, user.company_id)
    incident = Incident(
        company_id=user.company_id,
        created_by_id=user.id,
        assigned_to_id=assigned.id if assigned else None,
        analysis_id=analysis.id if analysis else None,
        alert_id=alert.id if alert else None,
        title=payload.title.strip(),
        severity=alert.severity if alert else "Medium",
    )
    db.add(incident)
    db.flush()
    for associated_analysis_id in analysis_ids:
        db.add(IncidentAnalysis(incident_id=incident.id, analysis_id=associated_analysis_id))
    db.add(IncidentEvent(incident_id=incident.id, actor_user_id=user.id, event_type="created", details="Incident created."))
    append_audit(
        db,
        "incident_created",
        "success",
        company_id=user.company_id,
        actor_user_id=user.id,
        resource_id=incident.id,
        details={"alert_id": incident.alert_id, "analysis_id": incident.analysis_id},
    )
    db.commit()
    return {"id": incident.id, "status": incident.status}


@router.patch("/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    incident = _incident(db, incident_id, user.company_id)
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="Provide an incident status or assignee to update.")
    if "assigned_to_id" in changes:
        assigned = _assigned_analyst(db, changes["assigned_to_id"], user.company_id)
        incident.assigned_to_id = assigned.id if assigned else None
        db.add(
            IncidentEvent(
                incident_id=incident.id,
                actor_user_id=user.id,
                event_type="assigned",
                details=f"Assigned to user {assigned.id}." if assigned else "Assignment cleared.",
            )
        )
    if "status" in changes and changes["status"] is not None:
        old_status = incident.status
        incident.status = changes["status"]
        db.add(
            IncidentEvent(
                incident_id=incident.id,
                actor_user_id=user.id,
                event_type="status_changed",
                details=f"Status changed from {old_status} to {incident.status}.",
            )
        )
    append_audit(
        db,
        "incident_updated",
        "success",
        company_id=user.company_id,
        actor_user_id=user.id,
        resource_id=incident.id,
        details=changes,
    )
    db.commit()
    return {"id": incident.id, "status": incident.status, "assigned_to_id": incident.assigned_to_id}


@router.post("/{incident_id}/notes", status_code=201)
def add_incident_note(
    incident_id: int,
    payload: IncidentNote,
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    incident = _incident(db, incident_id, user.company_id)
    note = payload.note.strip()
    if not note:
        raise HTTPException(status_code=422, detail="Investigation note cannot be empty.")
    event = IncidentEvent(
        incident_id=incident.id,
        actor_user_id=user.id,
        event_type="note",
        details=note,
    )
    db.add(event)
    append_audit(
        db,
        "incident_note_added",
        "success",
        company_id=user.company_id,
        actor_user_id=user.id,
        resource_id=incident.id,
    )
    db.commit()
    return _serialize_event(event)
