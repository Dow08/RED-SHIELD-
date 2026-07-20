"""État runtime mutable (ex. mode air-gapped modifiable sans redémarrer)."""
from __future__ import annotations

from app.config import settings


class Runtime:
    def __init__(self) -> None:
        self.airgapped: bool = settings.airgapped


runtime = Runtime()
