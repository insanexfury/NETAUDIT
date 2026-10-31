"""NetAudit FastAPI entry point and static dashboard host."""

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from app.api import routes_analysis, routes_auth, routes_comparator, routes_company, routes_evidence, routes_incidents, routes_notifications, routes_reports, routes_upload
from app.config import BASE_DIR, COOKIE_SECURE
from app.database.database import Base, engine
import app.database.models  # Registers models before table creation.
from app.database.migrations import upgrade_database
from app.services.detection_settings import default_policy
from app.services.security import create_guest_cookie, decode_guest_cookie, GUEST_COOKIE

default_policy()
Base.metadata.create_all(bind=engine)
upgrade_database(engine)
app = FastAPI(title="NetAudit", version="1.0.0", description="Automated PCAP and Network Traffic Analysis Toolkit")
app.include_router(routes_auth.router)
app.include_router(routes_company.router)
app.include_router(routes_upload.router)
app.include_router(routes_analysis.router)
app.include_router(routes_reports.router)
app.include_router(routes_comparator.router)
app.include_router(routes_incidents.router)
app.include_router(routes_notifications.router)
app.include_router(routes_evidence.router)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.middleware("http")
async def guest_session_middleware(request: Request, call_next):
    """Keep anonymous analysis history isolated to one signed guest browser session."""
    guest_id = decode_guest_cookie(request.cookies.get(GUEST_COOKIE))
    guest_token = None
    if guest_id is None:
        guest_id, guest_token = create_guest_cookie()
    request.state.guest_session_id = guest_id
    response = await call_next(request)
    if guest_token:
        response.set_cookie(
            GUEST_COOKIE,
            guest_token,
            max_age=24 * 60 * 60,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="strict",
            path="/",
        )
    return response


@app.get("/", include_in_schema=False)
def landing_page():
    """Offer the free guest flow and company workspace entry points."""
    return FileResponse(BASE_DIR / "templates" / "landing.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    """Serve the existing general PCAP analysis dashboard."""
    return FileResponse(BASE_DIR / "templates" / "index.html")


@app.get("/workspace", include_in_schema=False)
def company_workspace():
    """Serve the company administration and analysis workspace."""
    return FileResponse(BASE_DIR / "templates" / "workspace.html")


@app.get("/health")
def health_check():
    return {"status": "ok"}
