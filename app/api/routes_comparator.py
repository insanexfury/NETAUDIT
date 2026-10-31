"""Compare two PCAP captures using NetAudit's existing parsing and detection pipeline."""
from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile
import json
import logging

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import DetectionSettings, User
from app.services.comparator import compare_capture_files
from app.services.detection_settings import default_policy, validate_policy
from app.services.pcap_parser import PcapParseError, PcapTimeoutError
from app.services.security import enforce_rate_limit, get_optional_user, verify_csrf_for_authenticated_request
from app.utils.validators import validate_pcap_upload, validate_upload_size

router = APIRouter(tags=["comparator"])
logger = logging.getLogger(__name__)


def _store_uploaded_capture(file: UploadFile) -> Path:
    """Persist a validated upload to a safe temporary path for analysis."""
    validate_pcap_upload(file)
    with NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    size = 0
    try:
        with tmp_path.open("wb") as destination:
            while content := file.file.read(1024 * 1024):
                size += len(content)
                validate_upload_size(size)
                destination.write(content)
        if size == 0:
            raise HTTPException(status_code=400, detail="The uploaded PCAP is empty.")
        return tmp_path
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    finally:
        file.file.close()


@router.post("/compare")
def compare_pcap_upload(
    request: Request,
    file_a: UploadFile = File(...),
    file_b: UploadFile = File(...),
    user: User | None = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Compare two captures side by side using the existing analysis engine."""
    if user and user.role == "VIEWER/AUDITOR":
        raise HTTPException(status_code=403, detail="Viewer/Auditor accounts cannot initiate PCAP comparisons.")
    verify_csrf_for_authenticated_request(request)
    enforce_rate_limit("pcap-compare", str(user.id if user else request.state.guest_session_id), attempts=10, period_seconds=3600)
    policy = default_policy()
    if user:
        settings = db.get(DetectionSettings, user.company_id)
        if not settings:
            raise HTTPException(status_code=503, detail="Company detection settings are unavailable.")
        try:
            policy = validate_policy(json.loads(settings.settings_json))
        except (ValueError, json.JSONDecodeError):
            raise HTTPException(status_code=503, detail="Company detection settings are invalid.")
    if not file_a.filename or not file_b.filename:
        raise HTTPException(status_code=400, detail="Choose both PCAP files before comparing.")
    if file_a.filename == file_b.filename:
        raise HTTPException(status_code=400, detail="Choose two different PCAP files to compare.")

    temp_a = temp_b = None
    try:
        temp_a = _store_uploaded_capture(file_a)
        temp_b = _store_uploaded_capture(file_b)
        return compare_capture_files(temp_a, temp_b, policy)
    except HTTPException:
        raise
    except PcapTimeoutError as error:
        raise HTTPException(status_code=408, detail=str(error)) from error
    except PcapParseError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:
        logger.exception("PCAP comparison failed")
        raise HTTPException(status_code=500, detail="PCAP comparison could not be completed.") from error
    finally:
        for temp_path in (temp_a, temp_b):
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)
