"""Module Bande passante : débit réseau ↓/↑ en temps réel (net_io_counters).

Débit total réel (agrégé). Le débit par process (Top process en Mo/s) nécessite ETW
sous Windows / eBPF sous Linux — reporté ; d'ici là, cf. Shield.top_talkers (nombre de
connexions par process, réel).
"""
from __future__ import annotations

import time

import psutil
from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus


class Bandwidth(BaseModel):
    down_bps: float
    up_bps: float
    down_mo_s: float
    up_mo_s: float


class BandwidthModule(Module):
    name = "bandwidth"
    version = "0.1.0"
    description = "Débit réseau ↓/↑ (net_io_counters)"
    produces = ["bandwidth"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._last: tuple[int, int] | None = None
        self._last_t: float = 0.0

    def start(self) -> None:
        io = psutil.net_io_counters()
        self._last = (io.bytes_recv, io.bytes_sent)
        self._last_t = time.monotonic()
        self.set_status(ModuleStatus.ACTIVE)

    def get_rates(self) -> Bandwidth:
        io = psutil.net_io_counters()
        now = time.monotonic()
        if self._last is None:
            self._last = (io.bytes_recv, io.bytes_sent)
            self._last_t = now
            return Bandwidth(down_bps=0.0, up_bps=0.0, down_mo_s=0.0, up_mo_s=0.0)
        dt = max(now - self._last_t, 1e-6)
        down = max(0.0, (io.bytes_recv - self._last[0]) / dt)
        up = max(0.0, (io.bytes_sent - self._last[1]) / dt)
        self._last = (io.bytes_recv, io.bytes_sent)
        self._last_t = now
        return Bandwidth(down_bps=down, up_bps=up, down_mo_s=down / 1e6, up_mo_s=up / 1e6)
