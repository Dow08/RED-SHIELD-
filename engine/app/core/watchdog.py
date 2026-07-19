"""Watchdog : exécute une opération de module en attrapant tout crash.

Un module qui plante passe en ERROR, l'incident est journalisé sur le bus,
et l'application continue de tourner (les autres modules ne sont pas impactés).
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

log = logging.getLogger("red")


def supervise(module: Module, fn: Callable[[], Any], bus: EventBus | None, action: str = "run") -> Any:
    try:
        return fn()
    except Exception as exc:
        module.set_status(ModuleStatus.ERROR, f"{action}: {exc}")
        if bus is not None:
            bus.publish(
                "log",
                {"level": "error", "module": module.name, "message": f"{action}: {exc}"},
            )
        log.error("Module %s a échoué (%s): %s", module.name, action, exc)
        return None
