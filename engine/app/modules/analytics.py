"""Module Analytics — beaconing C2, baseline & timeline d'incidents.

Échantillonne périodiquement les connexions (via shield+scoring), construit une
timeline des événements (apparition/fermeture/alerte) et détecte le beaconing :
des connexions qui réapparaissent à intervalles réguliers (motif de C2).
Données réelles uniquement.
"""
from __future__ import annotations

import statistics
import threading
import time
from collections import deque
from datetime import datetime, timezone

from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus


class TimelineEvent(BaseModel):
    ts: str
    kind: str  # nouvelle_connexion / connexion_fermee / alerte
    severity: str
    process: str
    remote: str


class Beacon(BaseModel):
    process: str
    remote: str
    period_s: float
    count: int
    regularity: float  # 1.0 = parfaitement régulier


class AnalyticsModule(Module):
    name = "analytics"
    version = "0.1.0"
    description = "Beaconing, baseline & timeline"
    consumes = ["connections"]
    produces = ["timeline", "beaconing"]

    def __init__(self, bus: EventBus, shield, scoring, interval: float = 8.0) -> None:
        super().__init__(bus)
        self._shield = shield
        self._scoring = scoring
        self._interval = interval
        self._timeline: deque[TimelineEvent] = deque(maxlen=500)
        self._appearances: dict[tuple[str, str], deque[float]] = {}
        self._prev: dict[tuple[str, str], str] = {}
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.set_status(ModuleStatus.ACTIVE)

    def stop(self) -> None:
        self._stop.set()
        super().stop()

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._sample()
            except Exception as exc:
                self.bus.publish("log", {"level": "error", "module": self.name, "message": f"sample: {exc}"})

    def _sample(self) -> None:
        scored = self._scoring.score_connections(self._shield.get_connections())
        now = time.time()
        cur: dict[tuple[str, str], str] = {}
        for c in scored:
            cur[(c.process, c.remote_addr)] = c.severity
        for key, sev in cur.items():
            if key not in self._prev:
                self._appearances.setdefault(key, deque(maxlen=20)).append(now)
                self._event("nouvelle_connexion", sev, key)
                if sev in ("suspect", "crit"):
                    self._event("alerte", sev, key)
        for key in self._prev:
            if key not in cur:
                self._event("connexion_fermee", "safe", key)
        self._prev = cur

    def _event(self, kind: str, severity: str, key: tuple[str, str]) -> None:
        self._timeline.append(
            TimelineEvent(ts=datetime.now(timezone.utc).isoformat(), kind=kind, severity=severity, process=key[0], remote=key[1])
        )

    def timeline(self, limit: int = 100) -> list[TimelineEvent]:
        return list(self._timeline)[-limit:][::-1]

    def beaconing(self) -> list[Beacon]:
        out: list[Beacon] = []
        for (proc, remote), ts in self._appearances.items():
            if len(ts) < 4:
                continue
            intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
            mean = statistics.mean(intervals)
            if mean < 3:
                continue
            sd = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
            cv = sd / mean if mean else 1.0
            if cv < 0.25:  # intervalles réguliers → beaconing probable
                out.append(Beacon(process=proc, remote=remote, period_s=round(mean, 1), count=len(ts), regularity=round(1 - cv, 2)))
        return sorted(out, key=lambda b: -b.regularity)
