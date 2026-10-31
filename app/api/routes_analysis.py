"""Read-only APIs ensure the dashboard displays results stored in SQLite."""
import json
from datetime import timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import Alert, Analysis, Packet
from app.database.models import User
from app.services.security import get_analysis_for_user, get_optional_user

router = APIRouter(prefix="/analyses", tags=["analysis"])


@router.get("")
def list_analyses(
    request: Request,
    user: User | None = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List earlier PCAP investigations for dashboard selection."""
    query = db.query(Analysis)
    if user:
        query = query.filter(Analysis.company_id == user.company_id)
    else:
        query = query.filter(
            Analysis.company_id.is_(None),
            Analysis.guest_session_id == request.state.guest_session_id,
        )
    analyses = query.order_by(Analysis.id.desc()).all()
    return [{"id": item.id, "filename": item.filename, "status": item.status, "packet_count": item.packet_count, "threat_score": item.threat_score, "severity": item.severity, "uploaded_at": item.uploaded_at.isoformat()} for item in analyses]


@router.get("/{analysis_id}")
def analysis_details(
    analysis_id: int,
    request: Request,
    user: User | None = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Return persisted summary, findings, and chart data for one analysis."""
    analysis = get_analysis_for_user(analysis_id, user, request, db)
    alerts = db.query(Alert).filter(Alert.analysis_id == analysis_id).order_by(Alert.id).all()
    restricted = user is not None and user.role == "VIEWER/AUDITOR"
    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "status": analysis.status,
        "packet_count": analysis.packet_count,
        "duration": analysis.duration,
        "threat_score": analysis.threat_score,
        "severity": analysis.severity,
        "statistics": json.loads(analysis.statistics_json),
        "reasons": json.loads(analysis.threat_reasons_json),
        "config_version": analysis.config_version,
        "evidence_sha256": analysis.evidence_sha256,
        "alerts": [_serialize_alert(alert, restricted=restricted) for alert in alerts],
    }


@router.get("/{analysis_id}/packets")
def analysis_packets(
    analysis_id: int,
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    search: str = "",
    user: User | None = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Serve a bounded, searchable packet explorer directly from SQLite."""
    get_analysis_for_user(analysis_id, user, request, db)
    if user and user.role == "VIEWER/AUDITOR":
        raise HTTPException(status_code=403, detail="Viewer/Auditor accounts cannot access packet-level telemetry.")
    query = db.query(Packet).filter(Packet.analysis_id == analysis_id)
    if search:
        pattern = f"%{search}%"
        query = query.filter((Packet.src_ip.like(pattern)) | (Packet.dst_ip.like(pattern)) | (Packet.protocol.like(pattern)))
    return [_serialize_packet(packet) for packet in query.order_by(Packet.packet_number).limit(limit).all()]


def _serialize_alert(alert, restricted=False):
    serialized = {
        "id": alert.id,
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "score": alert.score,
        "timestamp": _utc_isoformat(alert.timestamp),
    }
    if not restricted:
        serialized.update(description=alert.description, evidence=alert.evidence)
    return serialized


def _serialize_packet(packet):
    return {"packet_number": packet.packet_number, "timestamp": _utc_isoformat(packet.timestamp), "src_ip": packet.src_ip, "dst_ip": packet.dst_ip, "protocol": packet.protocol, "src_port": packet.src_port, "dst_port": packet.dst_port, "packet_length": packet.packet_length, "tcp_flags": packet.tcp_flags, "dns_query": packet.dns_query, "http_host": packet.http_host, "http_method": packet.http_method, "http_uri": packet.http_uri}


def _utc_isoformat(timestamp):
    """Mark SQLite's UTC timestamps so browsers convert them to the user's locale."""
    return timestamp.replace(tzinfo=timezone.utc).isoformat() if timestamp else None
