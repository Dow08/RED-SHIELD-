"""Point d'entrée FastAPI de RED : coquille + endpoints de base.

Lancer : py -m uvicorn app.main:app --reload  (depuis engine/)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.config import settings
from app.core.bus import EventBus
from app.core.registry import Registry

logging.basicConfig(level=logging.INFO)


def register_modules(registry: Registry, bus: EventBus) -> None:
    """Enregistre les modules concrets. Rempli au fil des étapes (bouclier, diagnostic…)."""
    # (Étape 2+) registry.register(ShieldModule(bus)) etc.
    return None


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

    return app


app = create_app()
