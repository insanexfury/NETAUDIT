"""Verify additive migration preserves and explicitly scopes legacy analysis rows."""
from sqlalchemy import create_engine, text

from app.database.database import Base
from app.database.migrations import upgrade_database
import app.database.models


def test_legacy_rows_are_preserved_and_assigned_to_legacy_company(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE analyses (
                id INTEGER PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                uploaded_at DATETIME NOT NULL,
                status VARCHAR(30) NOT NULL,
                packet_count INTEGER NOT NULL,
                duration FLOAT NOT NULL,
                threat_score INTEGER NOT NULL,
                severity VARCHAR(20) NOT NULL,
                statistics_json TEXT NOT NULL,
                threat_reasons_json TEXT NOT NULL,
                error_message TEXT
            )
        """))
        connection.execute(text("""
            CREATE TABLE packets (
                id INTEGER PRIMARY KEY,
                analysis_id INTEGER NOT NULL,
                packet_number INTEGER NOT NULL,
                protocol VARCHAR(30) NOT NULL
            )
        """))
        connection.execute(text("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY,
                analysis_id INTEGER NOT NULL,
                alert_type VARCHAR(80) NOT NULL,
                severity VARCHAR(20) NOT NULL
            )
        """))
        connection.execute(text("""
            INSERT INTO analyses
            (id, filename, uploaded_at, status, packet_count, duration, threat_score, severity, statistics_json, threat_reasons_json)
            VALUES (7, 'legacy.pcap', '2025-01-01 00:00:00', 'complete', 1, 0, 0, 'Low', '{}', '[]')
        """))
        connection.execute(text("INSERT INTO packets (id, analysis_id, packet_number, protocol) VALUES (9, 7, 1, 'TCP')"))
        connection.execute(text("INSERT INTO alerts (id, analysis_id, alert_type, severity) VALUES (11, 7, 'Legacy finding', 'Low')"))

    Base.metadata.create_all(engine)
    upgrade_database(engine)

    with engine.connect() as connection:
        analysis = connection.execute(
            text("SELECT company_id, filename, packet_count FROM analyses WHERE id = 7")
        ).one()
        company = connection.execute(
            text("SELECT name FROM companies WHERE id = :id"), {"id": analysis.company_id}
        ).scalar_one()
        assert company == "Legacy NetAudit Workspace"
        assert (analysis.filename, analysis.packet_count) == ("legacy.pcap", 1)
        assert connection.execute(text("SELECT COUNT(*) FROM packets WHERE analysis_id = 7")).scalar_one() == 1
        assert connection.execute(text("SELECT COUNT(*) FROM alerts WHERE analysis_id = 7")).scalar_one() == 1
        assert connection.execute(
            text("SELECT COUNT(*) FROM detection_settings WHERE company_id = :id"),
            {"id": analysis.company_id},
        ).scalar_one() == 1
