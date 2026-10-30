"""NetAudit FastAPI entry point and static dashboard host."""

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from app.api import routes_analysis, routes_comparator, routes_reports, routes_upload
from app.database.database import Base, engine
import app.database.models  # Registers models before table creation.
from app.config import BASE_DIR

Base.metadata.create_all(bind=engine)
app = FastAPI(title="NetAudit", version="1.0.0", description="Automated PCAP and Network Traffic Analysis Toolkit")
app.include_router(routes_upload.router)
app.include_router(routes_analysis.router)
app.include_router(routes_reports.router)
app.include_router(routes_comparator.router)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/", include_in_schema=False)
def dashboard():
    """Serve the no-build HTML dashboard."""
    return FileResponse(BASE_DIR / "templates" / "index.html")


@app.get("/health")
def health_check():
    return {"status": "ok"}
