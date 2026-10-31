"""Provision the first administrator for a migrated legacy company workspace."""
from __future__ import annotations

import os
import sys

from sqlalchemy import func

from app.database.database import Base, SessionLocal, engine
from app.database.migrations import upgrade_database
from app.database.models import Company, User
from app.services.security import append_audit, generate_joining_code, hash_joining_code, hash_password


def main() -> int:
    required = ("BOOTSTRAP_ADMIN_NAME", "BOOTSTRAP_ADMIN_EMAIL", "BOOTSTRAP_ADMIN_USERNAME", "BOOTSTRAP_ADMIN_PASSWORD")
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        print("Set bootstrap administrator values in environment variables: " + ", ".join(missing), file=sys.stderr)
        return 2
    password = os.environ["BOOTSTRAP_ADMIN_PASSWORD"]
    if len(password) < 12:
        print("BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters.", file=sys.stderr)
        return 2

    Base.metadata.create_all(bind=engine)
    upgrade_database(engine)
    database = SessionLocal()
    try:
        company_name = os.getenv("BOOTSTRAP_COMPANY_NAME", "Legacy NetAudit Workspace").strip()
        company = database.query(Company).filter(func.lower(Company.name) == company_name.lower()).first()
        if not company:
            print("The requested company workspace does not exist.", file=sys.stderr)
            return 1
        if database.query(User.id).filter(User.company_id == company.id, User.role == "ADMIN", User.status == "APPROVED").first():
            print("This company already has an approved administrator.", file=sys.stderr)
            return 1

        username = os.environ["BOOTSTRAP_ADMIN_USERNAME"].strip().lower()
        email = os.environ["BOOTSTRAP_ADMIN_EMAIL"].strip().lower()
        if database.query(User.id).filter(
            (func.lower(User.username) == username) | (func.lower(User.email) == email)
        ).first():
            print("The bootstrap username or email is already in use.", file=sys.stderr)
            return 1

        admin = User(
            company_id=company.id,
            full_name=os.environ["BOOTSTRAP_ADMIN_NAME"].strip(),
            email=email,
            username=username,
            password_hash=hash_password(password),
            role="ADMIN",
            status="APPROVED",
        )
        database.add(admin)
        joining_code = generate_joining_code()
        company.joining_code_hash = hash_joining_code(joining_code)
        database.flush()
        append_audit(
            database,
            "legacy_admin_bootstrapped",
            "success",
            company_id=company.id,
            actor_user_id=admin.id,
            resource_id=admin.id,
        )
        database.commit()
        print(f"Administrator provisioned for {company.name}.")
        print(f"New company joining code (shown once): {joining_code}")
        return 0
    finally:
        database.close()


if __name__ == "__main__":
    raise SystemExit(main())
