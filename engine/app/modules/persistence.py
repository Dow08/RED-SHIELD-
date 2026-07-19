"""Module Persistence : historique des snapshots + audit (SQLite), avec budget ≤ 1 Go."""
from __future__ import annotations

import os
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine, select

from app.config import settings
from app.core.bus import EventBus
from app.models import AuditLog, Snapshot
from app.modules.base import Module, ModuleStatus


class PersistenceModule(Module):
    name = "persistence"
    version = "0.1.0"
    description = "Historique SQLite + audit"
    produces = ["history"]

    def __init__(self, bus: EventBus, db_url: str | None = None) -> None:
        super().__init__(bus)
        self._db_url = db_url or f"sqlite:///{settings.db_path}"
        self._file_path = self._db_url[len("sqlite:///"):] if self._db_url.startswith("sqlite:///") else None
        self._engine = None

    def start(self) -> None:
        if self._file_path:
            Path(self._file_path).parent.mkdir(parents=True, exist_ok=True)
        self._engine = create_engine(self._db_url, connect_args={"check_same_thread": False})
        SQLModel.metadata.create_all(self._engine)
        self.set_status(ModuleStatus.ACTIVE)

    def record_snapshot(self, summary) -> Snapshot:
        with Session(self._engine) as s:
            snap = Snapshot(
                exposure_score=summary.score,
                band=summary.band,
                total=summary.total,
                safe=summary.counts.get("safe", 0),
                watch=summary.counts.get("watch", 0),
                suspect=summary.counts.get("suspect", 0),
                crit=summary.counts.get("crit", 0),
            )
            s.add(snap)
            s.commit()
            s.refresh(snap)
        self.prune_to_budget()
        return snap

    def history(self, limit: int = 100) -> list[Snapshot]:
        with Session(self._engine) as s:
            return list(s.exec(select(Snapshot).order_by(Snapshot.taken_at.desc()).limit(limit)))

    def add_audit(self, action: str, detail: str = "") -> None:
        with Session(self._engine) as s:
            s.add(AuditLog(action=action, detail=detail))
            s.commit()

    def prune_to_budget(self) -> None:
        """Si la base dépasse le budget, supprime les snapshots les plus anciens (rotation)."""
        if not self._file_path:
            return
        try:
            size = os.path.getsize(self._file_path)
        except OSError:
            return
        if size <= settings.storage_budget_go * 1e9:
            return
        with Session(self._engine) as s:
            rows = list(s.exec(select(Snapshot).order_by(Snapshot.taken_at)))
            for row in rows[: max(1, len(rows) // 10)]:
                s.delete(row)
            s.commit()
