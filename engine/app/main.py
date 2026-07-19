"""Point d'entrée FastAPI de RED : coquille + endpoints de base.

Lancer : py -m uvicorn app.main:app --reload  (depuis engine/)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

from app import __version__
from app.config import settings
from app.core.bus import EventBus
from app.core.registry import Registry
from app.modules.base import ModuleStatus
from app.modules.bandwidth import BandwidthModule
from app.modules.diagnostic import DiagnosticModule
from app.modules.persistence import PersistenceModule
from app.modules.scoring import ScoringModule
from app.modules.shield import ShieldModule
from app.modules.trace import TraceModule
from app.modules.wifi import WifiModule
from app.report.markdown import build_markdown

logging.basicConfig(level=logging.INFO)


def register_modules(registry: Registry, bus: EventBus) -> None:
    """Enregistre les modules concrets (rempli au fil des étapes du Jalon 1).

    Diagnostic en premier : il s'abonne au bus avant les autres pour capter leurs logs.
    """
    registry.register(DiagnosticModule(bus))
    registry.register(ShieldModule(bus))
    registry.register(BandwidthModule(bus))
    registry.register(ScoringModule(bus))
    registry.register(PersistenceModule(bus))
    registry.register(TraceModule(bus))
    registry.register(WifiModule(bus))


def create_app() -> FastAPI:
    bus = EventBus()
    registry = Registry(bus)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        register_modules(registry, bus)
        registry.start_all()
        yield
        registry.stop_all()

    app = FastAPI(title="RED — Network Shield & Recon", version=__version__, lifespan=lifespan)
    app.state.bus = bus
    app.state.registry = registry

    # Un abonné défaillant est journalisé sans republier sur le bus (évite toute récursion).
    bus.set_error_handler(
        lambda topic, exc: logging.getLogger("red").error("bus[%s]: %s", topic, exc)
    )

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "ok",
            "service": "RED",
            "version": __version__,
            "airgapped": settings.airgapped,
        }

    @app.get("/modules", response_model=list)
    def modules() -> list:
        return registry.list()

    def _require(name: str):
        module = registry.get(name)
        if module is None or module.health() != ModuleStatus.ACTIVE:
            raise HTTPException(status_code=503, detail=f"module '{name}' indisponible")
        return module

    @app.get("/shield/connections")
    def shield_connections() -> list:
        conns = _require("shield").get_connections()
        scoring = registry.get("scoring")
        if scoring is not None and scoring.health() == ModuleStatus.ACTIVE:
            return scoring.score_connections(conns)
        return conns

    @app.get("/shield/top-talkers")
    def shield_top_talkers() -> list:
        return _require("shield").top_talkers()

    @app.get("/bandwidth")
    def bandwidth():
        return _require("bandwidth").get_rates()

    @app.get("/exposure")
    def exposure():
        conns = _require("shield").get_connections()
        scoring = _require("scoring")
        return scoring.exposure_summary(scoring.score_connections(conns))

    @app.get("/diagnostic/logs")
    def diagnostic_logs(since: str | None = None, until: str | None = None, level: str | None = None):
        return _require("diagnostic").get_logs(since=since, until=until, level=level)

    @app.get("/diagnostic/logs/export", response_class=PlainTextResponse)
    def diagnostic_export():
        text = _require("diagnostic").export_text()
        return PlainTextResponse(
            text, headers={"Content-Disposition": "attachment; filename=red-logs.txt"}
        )

    @app.post("/snapshot")
    def snapshot():
        scoring = _require("scoring")
        persist = _require("persistence")
        summary = scoring.exposure_summary(scoring.score_connections(_require("shield").get_connections()))
        snap = persist.record_snapshot(summary)
        persist.add_audit("snapshot", f"score={summary.score}")
        return snap

    @app.get("/history")
    def history(limit: int = 100):
        return _require("persistence").history(limit=limit)

    @app.get("/trace")
    def trace(target: str | None = None):
        return _require("trace").get(target)

    @app.post("/trace/run")
    def trace_run(target: str | None = None):
        module = _require("trace")
        module.run_async(target or module.default_target)
        return {"running": True, "target": target or module.default_target}

    @app.get("/wifi/networks")
    def wifi_networks():
        module = registry.get("wifi")
        if module is None:
            return {"networks": [], "message": "module WiFi indisponible"}
        return module.result()

    @app.get("/report/markdown", response_class=PlainTextResponse)
    def report_markdown():
        scoring = _require("scoring")
        scored = scoring.score_connections(_require("shield").get_connections())
        summary = scoring.exposure_summary(scored)
        persist = registry.get("persistence")
        if persist is not None and persist.health() == ModuleStatus.ACTIVE:
            persist.add_audit("report", "markdown")
        return PlainTextResponse(
            build_markdown(summary, scored),
            headers={"Content-Disposition": "attachment; filename=red-report.md"},
        )

    return app


app = create_app()
