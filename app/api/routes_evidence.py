"""Company-scoped evidence integrity checks, manifest verification, and downloads."""
from __future__ import annotations

import hmac
import json
import logging
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from app.config import UPLOAD_DIR
from app.database.database import get_db
from app.database.models import User
from app.services.evidence import EvidenceError, decrypt_evidence_file, sha256_file, verify_manifest
from app.services.security import append_audit, get_analysis_for_user, get_current_user, get_optional_user, require_csrf, require_roles

router = APIRouter(prefix="/analyses", tags=["evidence"])
logger = logging.getLogger(__name__)


def _stored_path(relative_path: str) -> Path:
    root = UPLOAD_DIR.resolve()
    path = (root / relative_path).resolve()
    if not path.is_relative_to(root):
        raise HTTPException(status_code=404, detail="Evidence file not found.")
    return path


@router.get("/{analysis_id}/evidence/manifest")
def get_evidence_manifest(
    analysis_id: int,
    request: Request,
    user: User | None = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    analysis = get_analysis_for_user(analysis_id, user, request, db)
    if not user or analysis.company_id is None or not analysis.evidence_manifest_json:
        raise HTTPException(status_code=404, detail="Evidence manifest not found.")
    return {
        "manifest": json.loads(analysis.evidence_manifest_json),
        "signature": analysis.evidence_signature,
        "signer_fingerprint": analysis.signer_fingerprint,
    }


@router.post("/{analysis_id}/evidence/verify")
def verify_evidence(
    analysis_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    analysis = get_analysis_for_user(analysis_id, user, request, db)
    if analysis.company_id is None or not analysis.evidence_path or not analysis.evidence_sha256:
        raise HTTPException(status_code=404, detail="Stored company evidence is not available for verification.")

    evidence_path = _stored_path(analysis.evidence_path)
    temporary_path: Path | None = None
    hash_valid = False
    signature_valid: bool | None = None
    failure = None
    try:
        if not evidence_path.is_file():
            failure = "Evidence file is missing."
        else:
            path_to_hash = evidence_path
            if analysis.evidence_encrypted:
                temporary_file = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
                temporary_path = Path(temporary_file.name)
                temporary_file.close()
                decrypt_evidence_file(evidence_path, temporary_path)
                path_to_hash = temporary_path
            hash_valid = hmac.compare_digest(sha256_file(path_to_hash), analysis.evidence_sha256)
            if not hash_valid:
                failure = "The stored evidence hash does not match the recorded hash."
    except EvidenceError:
        failure = "Evidence authentication or decryption failed."
    except OSError:
        logger.exception("Could not read evidence for analysis %s", analysis_id)
        failure = "Evidence could not be read."
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink(missing_ok=True)

    if analysis.evidence_signature and analysis.evidence_manifest_json:
        try:
            signature_valid = verify_manifest(
                json.loads(analysis.evidence_manifest_json),
                analysis.evidence_signature,
                analysis.signer_fingerprint,
            )
        except EvidenceError:
            signature_valid = False
    integrity_verified = hash_valid and (signature_valid is True)
    if signature_valid is None and hash_valid:
        failure = "The content hash matches, but no trusted digital signature is available."
    elif signature_valid is False and failure is None:
        failure = "The evidence manifest signature is invalid or untrusted."

    append_audit(
        db,
        "evidence_hash_verified",
        "success" if hash_valid else "failed",
        company_id=user.company_id,
        actor_user_id=user.id,
        resource_id=analysis.id,
        details={
            "hash_valid": hash_valid,
            "signature_valid": signature_valid,
            "integrity_verified": integrity_verified,
        },
    )
    db.commit()
    return {
        "analysis_id": analysis.id,
        "hash_valid": hash_valid,
        "signature_valid": signature_valid,
        "integrity_verified": integrity_verified,
        "sha256": analysis.evidence_sha256,
        "message": failure or "Evidence hash and trusted manifest signature are valid.",
    }


@router.get("/{analysis_id}/evidence/download")
def download_evidence(
    analysis_id: int,
    request: Request,
    user: User = Depends(require_roles("ADMIN", "SECURITY_ANALYST")),
    db: Session = Depends(get_db),
):
    analysis = get_analysis_for_user(analysis_id, user, request, db)
    if not analysis.evidence_path:
        raise HTTPException(status_code=404, detail="Stored evidence is not available.")
    stored_path = _stored_path(analysis.evidence_path)
    if not stored_path.is_file():
        raise HTTPException(status_code=404, detail="Stored evidence is not available.")

    response_path = stored_path
    background = None
    if analysis.evidence_encrypted:
        try:
            temporary_file = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
            response_path = Path(temporary_file.name)
            temporary_file.close()
            decrypt_evidence_file(stored_path, response_path)
        except EvidenceError as error:
            if response_path != stored_path and response_path.exists():
                response_path.unlink(missing_ok=True)
            raise HTTPException(status_code=422, detail="Evidence decryption failed; no data was returned.") from error
        background = BackgroundTask(response_path.unlink, missing_ok=True)

    append_audit(
        db,
        "evidence_downloaded",
        "success",
        company_id=user.company_id,
        actor_user_id=user.id,
        resource_id=analysis.id,
    )
    db.commit()
    return FileResponse(
        response_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=analysis.filename,
        background=background,
    )


@router.post("/{analysis_id}/evidence/verify-signature")
def verify_evidence_signature(
    analysis_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    analysis = get_analysis_for_user(analysis_id, user, request, db)
    if not analysis.evidence_manifest_json or not analysis.evidence_signature:
        raise HTTPException(status_code=404, detail="A signed evidence manifest is not available.")
    try:
        valid = verify_manifest(
            json.loads(analysis.evidence_manifest_json),
            analysis.evidence_signature,
            analysis.signer_fingerprint,
        )
    except EvidenceError as error:
        raise HTTPException(status_code=503, detail="Trusted evidence verification key is unavailable.") from error
    append_audit(
        db,
        "evidence_signature_verified",
        "success" if valid else "failed",
        company_id=user.company_id,
        actor_user_id=user.id,
        resource_id=analysis.id,
        details={"signature_valid": valid},
    )
    db.commit()
    return {"analysis_id": analysis.id, "signature_valid": valid}
