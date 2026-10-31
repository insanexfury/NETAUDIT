"""Central configuration keeps demo thresholds visible and easy to explain."""
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"
DATABASE_URL = f"sqlite:///{DATA_DIR / 'netaudit.db'}"
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", 50 * 1024 * 1024))
MAX_PROCESSING_SECONDS = int(os.getenv("MAX_PROCESSING_SECONDS", 180))
TIME_WINDOW_SECONDS = int(os.getenv("TIME_WINDOW_SECONDS", 10))
PORT_SCAN_UNIQUE_PORTS = int(os.getenv("PORT_SCAN_UNIQUE_PORTS", 15))
BRUTE_FORCE_ATTEMPTS = int(os.getenv("BRUTE_FORCE_ATTEMPTS", 8))
VOLUME_MULTIPLIER = float(os.getenv("VOLUME_MULTIPLIER", 3.0))
AUTHENTICATION_PORTS = {21, 22, 23, 25, 110, 143, 3389}
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
SESSION_SECRET = os.getenv("SESSION_SECRET") or None
EVIDENCE_ENCRYPTION_KEY = os.getenv("EVIDENCE_ENCRYPTION_KEY") or None
EVIDENCE_SIGNING_PRIVATE_KEY = os.getenv("EVIDENCE_SIGNING_PRIVATE_KEY") or None
EVIDENCE_SIGNING_PUBLIC_KEY = os.getenv("EVIDENCE_SIGNING_PUBLIC_KEY") or None

for directory in (UPLOAD_DIR, REPORT_DIR, DATA_DIR):
    directory.mkdir(parents=True, exist_ok=True)
