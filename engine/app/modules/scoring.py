"""Module Scoring & corrélation MITRE : enrichit les connexions et calcule l'exposition."""
from __future__ import annotations

from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus
from app.modules.shield import Connection
from app.scoring.baseline import Baseline
from app.scoring.mitre import mitre_tags
from app.scoring.rules import score_connection, severity_of


class ScoredConnection(Connection):
    risk: int
    severity: str
    reasons: list[str] = []
    mitre: list[dict] = []


class ExposureSummary(BaseModel):
    score: int
    band: str  # faible / elevee / critique
    total: int
    counts: dict[str, int]


class ScoringModule(Module):
    name = "scoring"
    version = "0.1.0"
    description = "Scoring de risque + corrélation MITRE"
    consumes = ["connections"]
    produces = ["scored_connections", "exposure"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self.baseline = Baseline()

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    def score_connections(self, conns: list[Connection]) -> list[ScoredConnection]:
        warming = not self.baseline.warmed
        scored: list[ScoredConnection] = []
        for conn in conns:
            is_new = (not warming) and self.baseline.is_new(conn)
            risk, reasons = score_connection(conn, is_new=is_new)
            scored.append(
                ScoredConnection(
                    **conn.model_dump(),
                    risk=risk,
                    severity=severity_of(risk),
                    reasons=reasons,
                    mitre=mitre_tags(conn),
                )
            )
            self.baseline.learn(conn)
        self.baseline.warmed = True
        return scored

    def exposure_summary(self, scored: list[ScoredConnection]) -> ExposureSummary:
        counts = {"safe": 0, "watch": 0, "suspect": 0, "crit": 0}
        max_risk = 0
        for s in scored:
            counts[s.severity] = counts.get(s.severity, 0) + 1
            max_risk = max(max_risk, s.risk)
        score = min(
            100,
            round(0.6 * max_risk + 6 * counts["crit"] + 3 * counts["suspect"] + counts["watch"]),
        )
        if score <= 30:
            band = "faible"
        elif score <= 70:
            band = "elevee"
        else:
            band = "critique"
        return ExposureSummary(score=score, band=band, total=len(scored), counts=counts)
