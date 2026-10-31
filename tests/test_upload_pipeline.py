"""End-to-end API test: upload -> parse -> SQLite -> analysis result."""
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.database import Base, get_db
from app.main import app
import app.api.routes_upload as upload_routes


def test_upload_runs_persistence_and_detection(monkeypatch, tmp_path):
    test_engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    TestSession = sessionmaker(bind=test_engine)
    Base.metadata.create_all(test_engine)
    def override_database():
        database = TestSession()
        try: yield database
        finally: database.close()
    start = datetime(2025, 1, 1)
    def fake_parser(_, timeout_seconds=None):
        for index, port in enumerate(range(20, 36)):
            yield {"timestamp": start + timedelta(seconds=index / 10), "packet_number": index + 1, "src_ip": "10.0.0.9", "dst_ip": "10.0.0.2", "protocol": "TCP", "src_port": 40000, "dst_port": port, "packet_length": 60, "tcp_flags": "0x0002", "dns_query": None, "http_host": None, "http_method": None, "http_uri": None}
    monkeypatch.setattr(upload_routes, "parse_pcap", fake_parser)
    app.dependency_overrides[get_db] = override_database
    try:
        client = TestClient(app)
        response = client.post("/upload", files={"file": ("scan.pcap", b"pcap-test", "application/octet-stream")})
        assert response.status_code == 200
        analysis = client.get(f"/analyses/{response.json()['analysis_id']}").json()
        assert analysis["packet_count"] == 16
        assert analysis["statistics"]["total_packets"] == 16
        assert any(alert["alert_type"] == "Possible Port Scan" for alert in analysis["alerts"])
    finally:
        app.dependency_overrides.clear()


def test_compare_route_returns_summary_delta(monkeypatch):
    def fake_compare(path_a, path_b, policy=None):
        return {
            "capture_a": {"filename": path_a.name, "packet_count": 4, "threat_score": 70},
            "capture_b": {"filename": path_b.name, "packet_count": 3, "threat_score": 40},
            "comparison": {
                "protocols": [{"label": "TCP", "a_count": 2, "b_count": 1, "a_percent": 50, "b_percent": 33.33, "difference": -1}],
                "source_ips": {"common": ["10.0.0.9"], "only_in_a": [], "only_in_b": []},
                "destination_ips": {"common": ["10.0.0.2"], "only_in_a": [], "only_in_b": []},
                "port_summary": {"common_destination_ports": [], "only_in_a": ["22"], "only_in_b": ["53"], "tcp_unique_ports": {"a": 2, "b": 1}, "udp_unique_ports": {"a": 0, "b": 1}},
                "alerts": {"shared_types": [], "only_in_a": ["Possible Port Scan"], "only_in_b": ["Possible Brute-Force Activity"], "counts": {"Possible Port Scan": {"a": 1, "b": 0}, "Possible Brute-Force Activity": {"a": 0, "b": 1}}},
                "score_delta": -30,
                "severity_shift": "Medium",
            },
        }

    monkeypatch.setattr("app.api.routes_comparator.compare_capture_files", fake_compare)
    response = TestClient(app).post("/compare", files={
        "file_a": ("capture_a.pcap", b"pcap-a", "application/octet-stream"),
        "file_b": ("capture_b.pcap", b"pcap-b", "application/octet-stream"),
    })
    assert response.status_code == 200
    payload = response.json()
    assert payload["capture_a"]["packet_count"] == 4
    assert payload["capture_b"]["packet_count"] == 3
    assert "comparison" in payload
    assert "protocols" in payload["comparison"]
    assert payload["comparison"]["score_delta"] == -30
