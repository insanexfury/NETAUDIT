"""Additive SQLite upgrades; existing packet, alert, and analysis rows are retained."""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from app.services.detection_settings import default_policy


ANALYSIS_COLUMNS = {
    "company_id": "INTEGER REFERENCES companies(id)",
    "guest_session_id": "VARCHAR(64)",
    "uploaded_by_id": "INTEGER REFERENCES users(id)",
    "config_snapshot_json": "TEXT NOT NULL DEFAULT '{}'",
    "config_version": "INTEGER",
    "evidence_sha256": "VARCHAR(64)",
    "evidence_path": "VARCHAR(512)",
    "evidence_encrypted": "BOOLEAN NOT NULL DEFAULT 0",
    "evidence_manifest_json": "TEXT",
    "evidence_signature": "TEXT",
    "signer_fingerprint": "VARCHAR(64)",
}


def upgrade_database(engine: Engine) -> None:
    """Apply non-destructive schema additions and explicitly scope legacy analyses."""
    inspector = inspect(engine)
    if "analyses" not in inspector.get_table_names():
        return

    existing_columns = {column["name"] for column in inspector.get_columns("analyses")}
    with engine.begin() as connection:
        for column_name, definition in ANALYSIS_COLUMNS.items():
            if column_name not in existing_columns:
                connection.execute(text(f"ALTER TABLE analyses ADD COLUMN {column_name} {definition}"))
        if "users" in inspector.get_table_names():
            user_columns = {column["name"] for column in inspector.get_columns("users")}
            if "session_version" not in user_columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
                )

        legacy_count = connection.execute(
            text("SELECT COUNT(*) FROM analyses WHERE company_id IS NULL AND guest_session_id IS NULL")
        ).scalar_one()
        if legacy_count:
            legacy_company_id = connection.execute(
                text("SELECT id FROM companies WHERE name = :name"),
                {"name": "Legacy NetAudit Workspace"},
            ).scalar_one_or_none()
            if legacy_company_id is None:
                code_hash = hashlib.sha256(secrets.token_urlsafe(32).encode("utf-8")).hexdigest()
                result = connection.execute(
                    text(
                        "INSERT INTO companies (name, joining_code_hash, created_at) "
                        "VALUES (:name, :code_hash, :created_at)"
                    ),
                    {
                        "name": "Legacy NetAudit Workspace",
                        "code_hash": code_hash,
                        "created_at": datetime.utcnow(),
                    },
                )
                legacy_company_id = result.lastrowid
                connection.execute(
                    text(
                        "INSERT INTO detection_settings (company_id, version, settings_json, updated_at) "
                        "VALUES (:company_id, 1, :settings, :updated_at)"
                    ),
                    {
                        "company_id": legacy_company_id,
                        "settings": json.dumps(default_policy(), sort_keys=True),
                        "updated_at": datetime.utcnow(),
                    },
                )
            connection.execute(
                text(
                    "UPDATE analyses SET company_id = :company_id "
                    "WHERE company_id IS NULL AND guest_session_id IS NULL"
                ),
                {"company_id": legacy_company_id},
            )

        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_analyses_company_id ON analyses (company_id)")
        )
        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_analyses_guest_session_id ON analyses (guest_session_id)")
        )
        connection.execute(
            text("CREATE UNIQUE INDEX IF NOT EXISTS uq_companies_name_lower ON companies (lower(name))")
        )
