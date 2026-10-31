"""Validated, versioned per-company detection policy defaults."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.config import (
    BRUTE_FORCE_ATTEMPTS,
    PORT_SCAN_UNIQUE_PORTS,
    TIME_WINDOW_SECONDS,
    VOLUME_MULTIPLIER,
)


class DetectionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)

    time_window_seconds: int = Field(default=TIME_WINDOW_SECONDS, ge=1, le=300)
    port_scan_unique_ports: int = Field(default=PORT_SCAN_UNIQUE_PORTS, ge=3, le=65535)
    brute_force_attempts: int = Field(default=BRUTE_FORCE_ATTEMPTS, ge=3, le=10000)
    volume_multiplier: float = Field(default=VOLUME_MULTIPLIER, ge=1.1, le=100)
    ddos_min_packets: int = Field(default=100, ge=10, le=1_000_000)
    ddos_min_bytes: int = Field(default=100_000, ge=1_000, le=1_000_000_000)
    ddos_min_unique_sources: int = Field(default=10, ge=3, le=100_000)
    ddos_destination_share: float = Field(default=0.6, ge=0.1, le=1)
    syn_flood_min_packets: int = Field(default=100, ge=10, le=1_000_000)
    syn_flood_min_unique_sources: int = Field(default=5, ge=1, le=100_000)
    syn_flood_incomplete_ratio: float = Field(default=0.8, ge=0.1, le=1)
    score_port_scan: int = Field(default=40, ge=0, le=100)
    score_brute_force: int = Field(default=40, ge=0, le=100)
    score_abnormal_volume: int = Field(default=30, ge=0, le=100)
    score_ddos: int = Field(default=45, ge=0, le=100)
    score_syn_flood: int = Field(default=45, ge=0, le=100)


def default_policy() -> dict[str, Any]:
    return DetectionPolicy().model_dump()


def validate_policy(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict) or set(data) != set(DetectionPolicy.model_fields):
        raise ValueError("Detection configuration must contain every supported setting.")
    try:
        return DetectionPolicy.model_validate(data).model_dump()
    except ValidationError as error:
        raise ValueError("Detection configuration contains invalid or unsupported values.") from error
