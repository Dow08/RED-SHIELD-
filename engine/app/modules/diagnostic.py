"""Module Diagnostic : journal structuré des événements/erreurs, filtrable et exportable.

Les logs sont en mémoire (deque bornée) : bornés par nature et **purgés à la fermeture**
de l'application (rétention de session). Le budget disque ≤ 1 Go concerne la base SQLite
(cf. module Persistence). Le module s'abonne au bus et capte les erreurs des autres modules.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone

from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus


class LogEntry(BaseModel):
    ts: str
    level: str
    module: str = ""
    message: str = ""


class DiagnosticModule(Module):
    name = "diagnostic"
    version = "0.1.0"
    description = "Journal & auto-surveillance"
    consumes = ["log"]

    def __init__(self, bus: EventBus, maxlen: int = 5000) -> None:
        super().__init__(bus)
        self._logs: deque[LogEntry] = deque(maxlen=maxlen)

    def start(self) -> None:
        self.bus.subscribe("log", self._on_log)
        self.set_status(ModuleStatus.ACTIVE)
        self.add("info", "diagnostic", "module démarré")

    def _on_log(self, payload) -> None:
        if isinstance(payload, dict):
            self.add(
                payload.get("level", "info"),
                payload.get("module", ""),
                payload.get("message", ""),
            )

    def add(self, level: str, module: str, message: str) -> None:
        self._logs.append(
            LogEntry(
                ts=datetime.now(timezone.utc).isoformat(),
                level=level,
                module=module,
                message=message,
            )
        )

    def get_logs(
        self, since: str | None = None, until: str | None = None, level: str | None = None
    ) -> list[LogEntry]:
        result: list[LogEntry] = []
        for entry in self._logs:
            if level and entry.level != level:
                continue
            if since and entry.ts < since:
                continue
            if until and entry.ts > until:
                continue
            result.append(entry)
        return result

    def export_text(self, **filters) -> str:
        return "\n".join(
            f"{e.ts} [{e.level.upper():5}] {e.module}: {e.message}"
            for e in self.get_logs(**filters)
        )
