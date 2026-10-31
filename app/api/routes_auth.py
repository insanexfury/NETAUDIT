"""Company creation, employee onboarding, and cookie-session authentication."""
from __future__ import annotations

import json
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Company, DetectionSettings, User
from app.services.detection_settings import default_policy
from app.services.security import (
    append_audit,
    client_address,
    enforce_rate_limit,
    generate_joining_code,
    get_current_user,
    get_optional_user,
    hash_joining_code,
    hash_password,
    new_session_cookie,
    clear_session_cookie,
    require_csrf,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["authentication"])


class RegistrationFields(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    full_name: str = Field(min_length=2, max_length=160)
    email: str = Field(min_length=5, max_length=254)
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)
    confirm_password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        normalized = value.lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
            raise ValueError("Enter a valid work email address.")
        return normalized

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", value):
            raise ValueError("Use 3–64 letters, numbers, dots, dashes, or underscores for the username.")
        return value.lower()

    @field_validator("password")
    @classmethod
    def password_policy(cls, value: str) -> str:
        if len(set(value)) < 5 or value.isspace():
            raise ValueError("Choose a stronger password with varied characters.")
        return value

    def ensure_confirmation(self) -> None:
        if self.password != self.confirm_password:
            raise HTTPException(status_code=422, detail="Password and confirmation do not match.")


class CompanyRegistration(RegistrationFields):
    company_name: str = Field(min_length=2, max_length=160)


class EmployeeRegistration(RegistrationFields):
    joining_code: str = Field(min_length=20, max_length=128)
    requested_role: Literal["SECURITY_ANALYST", "VIEWER/AUDITOR"]


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


def _existing_identity(db: Session, username: str, email: str) -> bool:
    return db.query(User.id).filter(
        (func.lower(User.username) == username.lower()) | (func.lower(User.email) == email.lower())
    ).first() is not None


@router.post("/register-company", status_code=201)
def register_company(
    payload: CompanyRegistration,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    payload.ensure_confirmation()
    enforce_rate_limit("company-registration", client_address(request), attempts=5)
    name = payload.company_name.strip()
    if db.query(Company.id).filter(func.lower(Company.name) == name.lower()).first():
        raise HTTPException(status_code=409, detail="A company with that name is already registered.")
    if _existing_identity(db, payload.username, payload.email):
        raise HTTPException(status_code=409, detail="That username or email is already in use.")

    joining_code = generate_joining_code()
    try:
        company = Company(name=name, joining_code_hash=hash_joining_code(joining_code))
        db.add(company)
        db.flush()
        admin = User(
            company_id=company.id,
            full_name=payload.full_name,
            email=payload.email,
            username=payload.username,
            password_hash=hash_password(payload.password),
            role="ADMIN",
            status="APPROVED",
        )
        db.add(admin)
        db.add(DetectionSettings(company_id=company.id, version=1, settings_json=json.dumps(default_policy(), sort_keys=True)))
        db.flush()
        append_audit(
            db,
            "company_registered",
            "success",
            company_id=company.id,
            actor_user_id=admin.id,
            resource_id=company.id,
        )
        db.commit()
        csrf_token = new_session_cookie(response, admin)
        return {
            "company": {"id": company.id, "name": company.name},
            "user": {"id": admin.id, "full_name": admin.full_name, "username": admin.username, "role": admin.role},
            "joining_code": joining_code,
            "csrf_token": csrf_token,
        }
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(status_code=409, detail="That company, username, or email is already registered.") from error
    except Exception:
        db.rollback()
        raise


@router.post("/join-company", status_code=202)
def join_company(payload: EmployeeRegistration, request: Request, db: Session = Depends(get_db)):
    payload.ensure_confirmation()
    enforce_rate_limit("join-registration", client_address(request), attempts=10)
    enforce_rate_limit(f"join-code:{client_address(request)}", hash_joining_code(payload.joining_code), attempts=10)
    company = db.query(Company).filter(Company.joining_code_hash == hash_joining_code(payload.joining_code)).first()
    if not company:
        raise HTTPException(status_code=400, detail="The joining code or registration details are invalid.")
    if _existing_identity(db, payload.username, payload.email):
        raise HTTPException(status_code=409, detail="That username or email is already in use.")

    applicant = User(
        company_id=company.id,
        full_name=payload.full_name,
        email=payload.email,
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.requested_role,
        status="PENDING",
    )
    db.add(applicant)
    try:
        db.flush()
        append_audit(
            db,
            "employee_registration",
            "pending",
            company_id=company.id,
            actor_user_id=applicant.id,
            resource_id=applicant.id,
            details={"requested_role": applicant.role},
        )
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(status_code=409, detail="That username or email is already in use.") from error
    return {"status": "PENDING", "message": "Your request was sent to the company administrator."}


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    enforce_rate_limit("login", client_address(request), attempts=10)
    username = payload.username.strip().lower()
    user = db.query(User).filter(func.lower(User.username) == username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        append_audit(db, "login", "denied", details={"username": username[:64]})
        db.commit()
        raise HTTPException(status_code=401, detail="Username or password is incorrect.")
    if user.status != "APPROVED":
        append_audit(
            db,
            "login",
            "denied",
            company_id=user.company_id,
            actor_user_id=user.id,
            details={"account_status": user.status},
        )
        db.commit()
        raise HTTPException(status_code=403, detail="This account is pending approval or has been disabled.")
    append_audit(db, "login", "success", company_id=user.company_id, actor_user_id=user.id)
    db.commit()
    csrf_token = new_session_cookie(response, user)
    return {
        "user": {"id": user.id, "full_name": user.full_name, "username": user.username, "role": user.role},
        "csrf_token": csrf_token,
    }


@router.post("/logout")
def logout(
    response: Response,
    user: User = Depends(get_current_user),
    _csrf: None = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    append_audit(db, "logout", "success", company_id=user.company_id, actor_user_id=user.id)
    user.session_version += 1
    db.commit()
    clear_session_cookie(response)
    return {"status": "ok"}


@router.get("/me")
def current_session(request: Request, user: User | None = Depends(get_optional_user)):
    if user is None:
        return {"authenticated": False}
    payload = getattr(request.state, "session_payload", None) if request else None
    company = user.company_id
    return {
        "authenticated": True,
        "user": {
            "id": user.id,
            "full_name": user.full_name,
            "username": user.username,
            "role": user.role,
            "company_id": company,
        },
        "csrf_token": payload.get("csrf") if payload else None,
    }
