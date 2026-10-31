"""Tenant-aware upload pipeline reusing the existing PyShark analyzer."""
from __future__ import annotations

import json
import hashlib
import logging
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from app.config import MAX_PROCESSING_SECONDS, UPLOAD_DIR
from app.database.database import get_db
from app.database.models import Alert, Analysis, DetectionSettings, Packet, User
from app.services.analyzer import analyze_packets
from app.services.detection_settings import default_policy, validate_policy
from app.services.evidence import EvidenceError, encrypt_evidence_file, encryption_enabled, sign_manifest, signature_enabled
from app.services.notifications import publish_alert
from app.services.pcap_parser import PcapParseError, PcapTimeoutError, parse_pcap
from app.services.security import append_audit, enforce_rate_limit, get_optional_user, verify_csrf_for_authenticated_request
from app.utils.validators import validate_pcap_upload, validate_upload_size

router = APIRouter(tags=["upload"])
logger = logging.getLogger(__name__)


def _safe_display_name(filename: str | None) -> str:
    value = (filename or "capture.pcap").replace("\\", "/").rsplit("/", 1)[-1]
    value = re.sub(r"[\x00-\x1f\x7f]", "", value).strip()
    return value[:255] or "capture.pcap"


def _expire_guest_analyses(db: Session) -> None:
    cutoff = datetime.utcnow() - timedelta(hours=24)
    expired = db.query(Analysis).filter(
        Analysis.company_id.is_(None),
        Analysis.guest_session_id.is_not(None),
        Analysis.uploaded_at < cutoff,
    ).all()
    if expired:
        for analysis in expired:
            db.delete(analysis)
        db.commit()


def _record_failed_analysis(db: Session, analysis: Analysis, user: User | None) -> None:
    analysis_id = analysis.id
    if analysis_id is None:
        db.rollback()
        return
    try:
        db.rollback()
        analysis = db.get(Analysis, analysis_id)
        if analysis is None:
            return
        db.query(Packet).filter(Packet.analysis_id == analysis.id).delete(synchronize_session=False)
        db.query(Alert).filter(Alert.analysis_id == analysis.id).delete(synchronize_session=False)
        analysis.status = "failed"
        analysis.error_message = "Analysis did not complete; technical details are recorded in server logs."
        append_audit(
            db,
            "pcap_analysis_failed",
            "failed",
            company_id=analysis.company_id,
            actor_user_id=user.id if user else None,
            resource_id=analysis.id,
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not persist failed-analysis state")


@router.post("/upload")
def upload_pcap(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    user: User | None = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Parse a capture as a guest or with the authenticated user's company policy."""
    if user and user.role == "VIEWER/AUDITOR":
        append_audit(
            db,
            "pcap_upload_denied",
            "denied",
            company_id=user.company_id,
            actor_user_id=user.id,
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Viewer/Auditor accounts cannot upload PCAPs.")
    verify_csrf_for_authenticated_request(request)
    enforce_rate_limit("pcap-upload", str(user.id if user else request.state.guest_session_id), attempts=20, period_seconds=3600)
    validate_pcap_upload(file)
    _expire_guest_analyses(db)

    company_id = user.company_id if user else None
    guest_id = None if user else request.state.guest_session_id
    policy = default_policy()
    config_version = None
    if user:
        configuration = db.get(DetectionSettings, company_id)
        if not configuration:
            raise HTTPException(status_code=503, detail="Company detection settings are unavailable.")
        try:
            policy = validate_policy(json.loads(configuration.settings_json))
        except (ValueError, json.JSONDecodeError):
            raise HTTPException(status_code=503, detail="Company detection settings are invalid; contact the company administrator.")
        config_version = configuration.version

    stored_name = f"{uuid4().hex}.pcap"
    stored_path = UPLOAD_DIR / stored_name
    evidence_path: Path | None = None
    size = 0
    digest = hashlib.sha256()
    started_at = time.monotonic()
    analysis_started = False
    analysis = Analysis(
        company_id=company_id,
        guest_session_id=guest_id,
        uploaded_by_id=user.id if user else None,
        filename=_safe_display_name(file.filename),
        config_snapshot_json=json.dumps(policy, sort_keys=True),
        config_version=config_version,
    )
    try:
        with stored_path.open("wb") as destination:
            while content := file.file.read(1024 * 1024):
                size += len(content)
                validate_upload_size(size)
                digest.update(content)
                destination.write(content)
        if size == 0:
            raise HTTPException(status_code=400, detail="The uploaded PCAP is empty.")

        db.add(analysis)
        db.flush()
        append_audit(
            db,
            "pcap_analysis_started",
            "started",
            company_id=company_id,
            actor_user_id=user.id if user else None,
            resource_id=analysis.id,
            details={"filename": analysis.filename, "size_bytes": size},
        )
        db.commit()
        analysis_started = True
        packet_count = 0
        for telemetry in parse_pcap(stored_path, timeout_seconds=MAX_PROCESSING_SECONDS):
            if time.monotonic() - started_at > MAX_PROCESSING_SECONDS:
                raise HTTPException(status_code=408, detail="PCAP analysis exceeded the configured processing time limit.")
            db.add(Packet(analysis_id=analysis.id, **telemetry))
            packet_count += 1
            if packet_count % 500 == 0:
                db.flush()
        if packet_count == 0:
            raise HTTPException(status_code=400, detail="No readable packets were found in this PCAP.")
        db.flush()
        packets = db.query(Packet).filter(Packet.analysis_id == analysis.id).order_by(Packet.packet_number).all()
        statistics, found_alerts, score, severity, reasons = analyze_packets(packets, policy)
        for alert_data in found_alerts:
            db.add(Alert(analysis_id=analysis.id, **alert_data))
        analysis.packet_count = packet_count
        analysis.duration = statistics["duration"]
        analysis.threat_score = score
        analysis.severity = severity
        analysis.statistics_json = json.dumps(statistics)
        analysis.threat_reasons_json = json.dumps(reasons)
        analysis.evidence_sha256 = digest.hexdigest()

        if user:
            try:
                if encryption_enabled():
                    evidence_path = encrypt_evidence_file(stored_path)
                    analysis.evidence_encrypted = True
                else:
                    evidence_path = stored_path
                analysis.evidence_path = str(evidence_path.relative_to(UPLOAD_DIR))
                manifest = {
                    "analysis_id": analysis.id,
                    "company_id": company_id,
                    "pcap_sha256": analysis.evidence_sha256,
                    "submitter_user_id": user.id,
                    "submitted_at": analysis.uploaded_at.isoformat(),
                    "configuration_version": config_version,
                }
                analysis.evidence_manifest_json = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
                if signature_enabled():
                    analysis.evidence_signature, analysis.signer_fingerprint = sign_manifest(manifest)
            except EvidenceError as error:
                raise HTTPException(status_code=503, detail=str(error)) from error
        else:
            stored_path.unlink(missing_ok=True)

        analysis.status = "complete"
        append_audit(
            db,
            "pcap_analysis_completed",
            "success",
            company_id=company_id,
            actor_user_id=user.id if user else None,
            resource_id=analysis.id,
            details={"packet_count": packet_count, "sha256": analysis.evidence_sha256},
        )
        db.commit()

        if company_id:
            for alert in found_alerts:
                background_tasks.add_task(
                    publish_alert,
                    company_id,
                    {
                        "type": "alert",
                        "alert_type": alert["alert_type"],
                        "timestamp": alert["timestamp"].isoformat() if alert.get("timestamp") else None,
                        "severity": alert["severity"],
                        "threat_score": score,
                        "src_ip": alert.get("src_ip"),
                        "dst_ip": alert.get("dst_ip"),
                        "description": alert["description"],
                        "evidence": alert["evidence"],
                    },
                )
        return {
            "analysis_id": analysis.id,
            "status": analysis.status,
            "packet_count": packet_count,
            "threat_score": score,
            "severity": severity,
            "evidence_sha256": analysis.evidence_sha256,
            "config_version": config_version,
        }
    except HTTPException:
        if analysis_started:
            _record_failed_analysis(db, analysis, user)
        else:
            db.rollback()
        if stored_path.exists():
            stored_path.unlink(missing_ok=True)
        if evidence_path and evidence_path.exists():
            evidence_path.unlink(missing_ok=True)
        raise
    except PcapTimeoutError as error:
        if analysis_started:
            _record_failed_analysis(db, analysis, user)
        else:
            db.rollback()
        if stored_path.exists():
            stored_path.unlink(missing_ok=True)
        if evidence_path and evidence_path.exists():
            evidence_path.unlink(missing_ok=True)
        raise HTTPException(status_code=408, detail=str(error)) from error
    except PcapParseError as error:
        if analysis_started:
            _record_failed_analysis(db, analysis, user)
        else:
            db.rollback()
        if stored_path.exists():
            stored_path.unlink(missing_ok=True)
        if evidence_path and evidence_path.exists():
            evidence_path.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:
        logger.exception("PCAP analysis failed")
        if analysis_started:
            _record_failed_analysis(db, analysis, user)
        else:
            db.rollback()
        if stored_path.exists():
            stored_path.unlink(missing_ok=True)
        if evidence_path and evidence_path.exists():
            evidence_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Analysis could not be completed. Check server logs for details.") from error
    finally:
        file.file.close()
