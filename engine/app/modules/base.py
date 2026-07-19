"""Contrat de module : ce que chaque brique de RED doit exposer."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from app.core.bus import EventBus


class ModuleStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    NOT_CONNECTED = "not_connected"
    NOT_INSTALLED = "not_installed"


class ModuleInfo(BaseModel):
    name: str
    version: str
    description: str
    status: ModuleStatus
    message: str = ""
    produces: list[str] = []
    consumes: list[str] = []
    requires: list[str] = []


class Module:
    """Classe de base. Un module concret surcharge les attributs et start/stop/health."""

    name: str = "base"
    version: str = "0.1.0"
    description: str = ""
    produces: list[str] = []
    consumes: list[str] = []
    requires: list[str] = []

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self._status: ModuleStatus = ModuleStatus.INACTIVE
        self._message: str = ""

    def start(self) -> None:
        """Démarre le module. Surcharger. Doit lever en cas d'échec (le watchdog gère)."""
        self._status = ModuleStatus.ACTIVE

    def stop(self) -> None:
        """Arrête proprement le module. Surcharger si nécessaire."""
        self._status = ModuleStatus.INACTIVE

    def health(self) -> ModuleStatus:
        """État de santé courant (auto-diagnostic). Surcharger si besoin."""
        return self._status

    def set_status(self, status: ModuleStatus, message: str = "") -> None:
        self._status = status
        self._message = message

    def info(self) -> ModuleInfo:
        return ModuleInfo(
            name=self.name,
            version=self.version,
            description=self.description,
            status=self._status,
            message=self._message,
            produces=self.produces,
            consumes=self.consumes,
            requires=self.requires,
        )
