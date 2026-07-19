"""Modèles de données SQLite (SQLModel)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Snapshot(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    taken_at: datetime = Field(default_factory=_now, index=True)
    exposure_score: int
    band: str
    total: int
    safe: int = 0
    watch: int = 0
    suspect: int = 0
    crit: int = 0


class AuditLog(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=_now, index=True)
    action: str
    detail: str = ""
