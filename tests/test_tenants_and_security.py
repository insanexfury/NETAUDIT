"""Integration coverage for onboarding, tenant scoping, and policy snapshots."""
import base64
from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.database.database import Base, get_db
from app.main import app
import app.api.routes_evidence as evidence_routes
import app.api.routes_upload as upload_routes
from app.services import evidence


def _registration(company, username, email):
    return {
        "company_name": company,
        "full_name": f"{username.title()} Admin",
        "email": email,
        "username": username,
        "password": "AdminPassword!234",
        "confirm_password": "AdminPassword!234",
    }


def _fake_packets(_path, timeout_seconds=None):
    timestamp = datetime(2026, 1, 1)
    for index in range(16):
        yield {
            "timestamp": timestamp,
            "packet_number": index + 1,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 20 + index,
            "packet_length": 60,
            "tcp_flags": "0x0002",
            "dns_query": None,
            "http_host": None,
            "http_method": None,
            "http_uri": None,
        }


def _configured_client(tmp_path, monkeypatch):
    test_engine = create_engine(f"sqlite:///{tmp_path / 'tenant-test.db'}", connect_args={"check_same_thread": False})
    session_factory = sessionmaker(bind=test_engine)
    Base.metadata.create_all(test_engine)

    def override_database():
        database = session_factory()
        try:
            yield database
        finally:
            database.close()

    app.dependency_overrides[get_db] = override_database
    monkeypatch.setattr(upload_routes, "parse_pcap", _fake_packets)
    test_upload_dir = tmp_path / "uploads"
    test_upload_dir.mkdir()
    monkeypatch.setattr(upload_routes, "UPLOAD_DIR", test_upload_dir)
    monkeypatch.setattr(evidence_routes, "UPLOAD_DIR", test_upload_dir)
    return TestClient(app)


def test_company_onboarding_isolation_roles_and_policies(tmp_path, monkeypatch):
    client_a = _configured_client(tmp_path, monkeypatch)
    client_b = TestClient(app)
    try:
        company_a = client_a.post("/auth/register-company", json=_registration("Tenant Alpha", "alphaadmin", "alpha@example.test"))
        company_b = client_b.post("/auth/register-company", json=_registration("Tenant Beta", "betaadmin", "beta@example.test"))
        assert company_a.status_code == 201
        assert company_b.status_code == 201
        assert client_a.post("/auth/register-company", json=_registration("Tenant Alpha", "otheradmin", "other@example.test")).status_code == 409
        admin_a = company_a.json()
        admin_b = company_b.json()
        headers_a = {"X-CSRF-Token": admin_a["csrf_token"]}
        headers_b = {"X-CSRF-Token": admin_b["csrf_token"]}

        joined = client_a.post(
            "/auth/join-company",
            json={
                "joining_code": admin_a["joining_code"],
                "full_name": "A Viewer",
                "email": "viewer-a@example.test",
                "username": "aviewer",
                "password": "ViewerPassword!234",
                "confirm_password": "ViewerPassword!234",
                "requested_role": "VIEWER/AUDITOR",
            },
        )
        assert joined.status_code == 202
        bad_code = client_a.post(
            "/auth/join-company",
            json={
                "joining_code": "this-is-an-invalid-company-joining-code",
                "full_name": "Invalid Join",
                "email": "invalid@example.test",
                "username": "invalidjoin",
                "password": "OtherPassword!234",
                "confirm_password": "OtherPassword!234",
                "requested_role": "SECURITY_ANALYST",
            },
        )
        assert bad_code.status_code == 400
        duplicate_request = client_a.post(
            "/auth/join-company",
            json={
                "joining_code": admin_a["joining_code"],
                "full_name": "A Viewer",
                "email": "viewer-a@example.test",
                "username": "aviewer",
                "password": "ViewerPassword!234",
                "confirm_password": "ViewerPassword!234",
                "requested_role": "VIEWER/AUDITOR",
            },
        )
        assert duplicate_request.status_code == 409
        assert client_a.post(
            "/auth/login",
            json={"username": "aviewer", "password": "ViewerPassword!234"},
        ).status_code == 403

        users_a = client_a.get("/company/users").json()
        viewer = next(row for row in users_a if row["username"] == "aviewer")
        approved = client_a.post(
            f"/company/requests/{viewer['id']}/decision",
            json={"status": "APPROVED", "role": "VIEWER/AUDITOR"},
            headers=headers_a,
        )
        assert approved.status_code == 200
        assert approved.json()["role"] == "VIEWER/AUDITOR"
        assert client_b.post(
            f"/company/requests/{viewer['id']}/decision",
            json={"status": "APPROVED", "role": "ADMIN"},
            headers=headers_b,
        ).status_code == 404

        settings_a = client_a.get("/company/settings").json()
        settings_b = client_b.get("/company/settings").json()
        new_policy = dict(settings_a["settings"], port_scan_unique_ports=5)
        changed = client_a.put("/company/settings", json=new_policy, headers=headers_a)
        assert changed.status_code == 200
        assert changed.json()["version"] == 2
        assert client_b.get("/company/settings").json()["settings"] == settings_b["settings"]

        uploaded = client_a.post(
            "/upload",
            files={"file": ("tenant-a.pcap", b"synthetic-pcap", "application/octet-stream")},
            headers=headers_a,
        )
        assert uploaded.status_code == 200
        analysis_id = uploaded.json()["analysis_id"]
        details_a = client_a.get(f"/analyses/{analysis_id}")
        assert details_a.status_code == 200
        assert details_a.json()["config_version"] == 2
        assert client_b.get(f"/analyses/{analysis_id}").status_code == 404
        b_upload = client_b.post(
            "/upload",
            files={"file": ("tenant-b.pcap", b"synthetic-pcap", "application/octet-stream")},
            headers=headers_b,
        )
        assert b_upload.status_code == 200
        analysis_b_id = b_upload.json()["analysis_id"]
        assert client_b.get(f"/analyses/{analysis_b_id}").json()["config_version"] == 1
        assert client_a.get(f"/analyses/{analysis_b_id}").status_code == 404
        alerts = details_a.json()["alerts"]
        incident_response = client_a.post(
            "/incidents",
            json={"title": "Investigate port-scan alert", "alert_id": alerts[0]["id"]},
            headers=headers_a,
        )
        assert incident_response.status_code == 201
        incident_id = incident_response.json()["id"]
        assert client_a.get(f"/incidents/{incident_id}").status_code == 200
        assert client_b.get(f"/incidents/{incident_id}").status_code == 404
        cross_tenant_incident = client_a.post(
            "/incidents",
            json={
                "title": "Invalid cross-company association",
                "analysis_ids": [analysis_id, analysis_b_id],
            },
            headers=headers_a,
        )
        assert cross_tenant_incident.status_code == 404

        viewer_client = TestClient(app)
        viewer_login = viewer_client.post(
            "/auth/login",
            json={"username": "aviewer", "password": "ViewerPassword!234"},
        )
        viewer_csrf = {"X-CSRF-Token": viewer_login.json()["csrf_token"]}
        assert viewer_client.get(f"/analyses/{analysis_id}/packets").status_code == 403
        viewer_detail = viewer_client.get(f"/analyses/{analysis_id}").json()
        assert all("evidence" not in alert for alert in viewer_detail["alerts"])
        assert viewer_client.get(f"/analyses/{analysis_id}/report").status_code == 200
        assert client_a.get("/company/audit").json()["chain_valid"] is True
        assert viewer_client.post(
            "/upload",
            files={"file": ("blocked.pcap", b"capture", "application/octet-stream")},
            headers=viewer_csrf,
        ).status_code == 403
        assert client_a.get("/company/users").status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_guest_analysis_is_private_to_browser_session(tmp_path, monkeypatch):
    client_a = _configured_client(tmp_path, monkeypatch)
    client_b = TestClient(app)
    try:
        response = client_a.post(
            "/upload",
            files={"file": ("guest.pcap", b"guest-pcap", "application/octet-stream")},
        )
        assert response.status_code == 200
        analysis_id = response.json()["analysis_id"]
        assert client_a.get(f"/analyses/{analysis_id}").status_code == 200
        assert client_b.get(f"/analyses/{analysis_id}").status_code == 404
        assert client_b.get("/analyses").json() == []
    finally:
        app.dependency_overrides.clear()


def test_company_evidence_encryption_signature_and_tamper_detection(tmp_path, monkeypatch):
    client = _configured_client(tmp_path, monkeypatch)
    key = b"0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(evidence, "EVIDENCE_ENCRYPTION_KEY", base64.urlsafe_b64encode(key).decode())
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(
        evidence,
        "EVIDENCE_SIGNING_PRIVATE_KEY",
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )
    monkeypatch.setattr(
        evidence,
        "EVIDENCE_SIGNING_PUBLIC_KEY",
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    )
    try:
        registration = client.post(
            "/auth/register-company",
            json=_registration("Evidence Tenant", "evidenceadmin", "evidence@example.test"),
        )
        csrf = {"X-CSRF-Token": registration.json()["csrf_token"]}
        uploaded = client.post(
            "/upload",
            files={"file": ("evidence.pcap", b"sealed-pcap", "application/octet-stream")},
            headers=csrf,
        )
        assert uploaded.status_code == 200
        analysis_id = uploaded.json()["analysis_id"]
        verification = client.post(f"/analyses/{analysis_id}/evidence/verify", headers=csrf)
        assert verification.json()["hash_valid"] is True
        assert verification.json()["signature_valid"] is True
        downloaded = client.get(f"/analyses/{analysis_id}/evidence/download")
        assert downloaded.status_code == 200
        assert downloaded.content == b"sealed-pcap"

        encrypted_path = next(upload_routes.UPLOAD_DIR.glob("*.pcap.enc"))
        tampered = bytearray(encrypted_path.read_bytes())
        tampered[-1] ^= 0x01
        encrypted_path.write_bytes(tampered)
        failed = client.post(f"/analyses/{analysis_id}/evidence/verify", headers=csrf)
        assert failed.status_code == 200
        assert failed.json()["hash_valid"] is False
        assert failed.json()["integrity_verified"] is False
    finally:
        app.dependency_overrides.clear()
