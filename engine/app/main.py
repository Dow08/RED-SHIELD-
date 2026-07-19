"""Point d'entrée FastAPI de RED : coquille + endpoints de base.

Lancer : py -m uvicorn app.main:app --reload  (depuis engine/)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from app import __version__
from app.config import settings
from app.core.bus import EventBus
from app.core.registry import Registry
from app.modules.base import ModuleStatus
from app.modules.bandwidth import BandwidthModule
from app.modules.scoring import ScoringModule
from app.modules.shield import ShieldModule

logging.basicConfig(level=logging.INFO)


def register_modules(registry: Registry, bus: EventBus) -> None:
    """Enregistre les modules concrets (rempli au fil des étapes du Jalon 1)."""
    registry.register(ShieldModule(bus))
    registry.register(BandwidthModule(bus))
    registry.register(ScoringModule(bus))


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

    return app


app = create_app()
