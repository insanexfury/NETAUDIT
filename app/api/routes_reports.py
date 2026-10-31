"""PDF route creates a report from persisted data, not dashboard-only state."""
import json
import logging
from types import SimpleNamespace
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import Alert, User
from app.services.report_generator import generate_report
from app.services.security import append_audit, get_analysis_for_user, get_optional_user

router = APIRouter(prefix="/analyses", tags=["reports"])
logger = logging.getLogger(__name__)


@router.get("/{analysis_id}/report")
def download_report(
    analysis_id: int,
    request: Request,
    user: User | None = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Generate and download the analysis PDF on demand."""
    analysis = get_analysis_for_user(analysis_id, user, request, db)
    if analysis.status != "complete":
        raise HTTPException(status_code=404, detail="A completed analysis was not found.")
    try:
        alerts = db.query(Alert).filter(Alert.analysis_id == analysis.id).all()
        if user and user.role == "VIEWER/AUDITOR":
            alerts = [
                SimpleNamespace(
                    severity=alert.severity,
                    alert_type=alert.alert_type,
                    evidence="Detailed evidence is restricted for Viewer/Auditor accounts.",
                )
                for alert in alerts
            ]
        report = generate_report(analysis, alerts, json.loads(analysis.statistics_json))
        append_audit(
            db,
            "report_exported",
            "success",
            company_id=user.company_id if user else None,
            actor_user_id=user.id if user else None,
            resource_id=analysis.id,
        )
        db.commit()
        background = BackgroundTask(report.unlink, missing_ok=True) if user is None else None
        return FileResponse(
            report,
            media_type="application/pdf",
            filename=f"NetAudit_{analysis.id}_report.pdf",
            background=background,
        )
    except Exception:
        db.rollback()
        logger.exception("PDF report generation failed for analysis %s", analysis_id)
        raise HTTPException(status_code=500, detail="PDF report generation failed.")
