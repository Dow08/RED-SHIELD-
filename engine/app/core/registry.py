"""Registre de modules : enregistre, démarre/arrête et liste les modules, sous supervision."""
from __future__ import annotations

from app.core.bus import EventBus
from app.core.watchdog import supervise
from app.modules.base import Module, ModuleInfo


class Registry:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._modules: dict[str, Module] = {}

    def register(self, module: Module) -> None:
        self._modules[module.name] = module

    def get(self, name: str) -> Module | None:
        return self._modules.get(name)

    def start_all(self) -> None:
        for module in self._modules.values():
            supervise(module, module.start, self.bus, "start")

    def stop_all(self) -> None:
        for module in self._modules.values():
            supervise(module, module.stop, self.bus, "stop")

    def list(self) -> list[ModuleInfo]:
        return [module.info() for module in self._modules.values()]
