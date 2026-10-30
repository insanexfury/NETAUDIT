"""Compare two PCAP captures using NetAudit's existing parsing and detection pipeline."""
from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.services.comparator import compare_capture_files
from app.utils.validators import validate_pcap_upload, validate_upload_size

router = APIRouter(tags=["comparator"])


def _store_uploaded_capture(file: UploadFile) -> Path:
    """Persist a validated upload to a safe temporary path for analysis."""
    validate_pcap_upload(file)
    with NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    data = file.file.read()
    file.file.close()
    size = len(data)
    validate_upload_size(size)
    if size == 0:
        raise HTTPException(status_code=400, detail="The uploaded PCAP is empty.")
    tmp_path.write_bytes(data)
    return tmp_path


@router.post("/compare")
def compare_pcap_upload(file_a: UploadFile = File(...), file_b: UploadFile = File(...), db: Session = Depends(get_db)):
    """Compare two captures side by side using the existing analysis engine."""
    del db
    if not file_a.filename or not file_b.filename:
        raise HTTPException(status_code=400, detail="Choose both PCAP files before comparing.")
    if file_a.filename == file_b.filename:
        raise HTTPException(status_code=400, detail="Choose two different PCAP files to compare.")

    temp_a = temp_b = None
    try:
        temp_a = _store_uploaded_capture(file_a)
        temp_b = _store_uploaded_capture(file_b)
        return compare_capture_files(temp_a, temp_b)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Comparison failed: {error}") from error
    finally:
        for temp_path in (temp_a, temp_b):
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)
