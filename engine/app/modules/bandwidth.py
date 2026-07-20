"""Module Bande passante : débit réseau ↓/↑ en temps réel (net_io_counters).

Débit total réel (agrégé) + ventilation **par interface** (pour voir les
fluctuations réelles et identifier l'adaptateur actif). Avertissement honnête :
certains adaptateurs tunnel VPN (WireGuard/NordLynx/WinTun) n'exposent pas leurs
compteurs d'octets à l'API Windows utilisée par psutil — le trafic qui y transite
peut donc être sous-compté. Pour un décompte exact quel que soit l'adaptateur,
utiliser la capture pktmon (onglet débit par processus, admin).
"""
from __future__ import annotations

import time

import psutil
from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

_TUNNEL_HINTS = ("nord", "tun", "tap", "wireguard", "wg", "vpn", "proton", "mullvad", "openvpn", "wintun")


def _is_tunnel(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in _TUNNEL_HINTS)


class NicRate(BaseModel):
    name: str
    down_mo_s: float
    up_mo_s: float
    is_tunnel: bool = False


class Bandwidth(BaseModel):
    down_bps: float
    up_bps: float
    down_mo_s: float
    up_mo_s: float
    nics: list[NicRate] = []
    note: str = ""


class BandwidthModule(Module):
    name = "bandwidth"
    version = "0.2.0"
    description = "Débit réseau ↓/↑ (net_io_counters, par interface)"
    produces = ["bandwidth"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._last: tuple[int, int] | None = None
        self._last_t: float = 0.0
        self._last_nic: dict[str, tuple[int, int]] = {}

    def start(self) -> None:
        io = psutil.net_io_counters()
        self._last = (io.bytes_recv, io.bytes_sent)
        self._last_t = time.monotonic()
        self._snapshot_nics()
        self.set_status(ModuleStatus.ACTIVE)

    def _snapshot_nics(self) -> None:
        try:
            per = psutil.net_io_counters(pernic=True)
        except Exception:
            return
        self._last_nic = {n: (v.bytes_recv, v.bytes_sent) for n, v in per.items()}

    def get_rates(self) -> Bandwidth:
        io = psutil.net_io_counters()
        now = time.monotonic()
        if self._last is None:
            self._last = (io.bytes_recv, io.bytes_sent)
            self._last_t = now
            self._snapshot_nics()
            return Bandwidth(down_bps=0.0, up_bps=0.0, down_mo_s=0.0, up_mo_s=0.0)
        dt = max(now - self._last_t, 1e-6)
        down = max(0.0, (io.bytes_recv - self._last[0]) / dt)
        up = max(0.0, (io.bytes_sent - self._last[1]) / dt)

        # Ventilation par interface (fluctuations réelles + détection tunnel VPN).
        nics: list[NicRate] = []
        tunnel_present = False
        try:
            per = psutil.net_io_counters(pernic=True)
        except Exception:
            per = {}
        for name, v in per.items():
            prev = self._last_nic.get(name)
            self._last_nic[name] = (v.bytes_recv, v.bytes_sent)
            tun = _is_tunnel(name)
            tunnel_present = tunnel_present or tun
            if prev is None:
                continue
            d = max(0.0, (v.bytes_recv - prev[0]) / dt)
            u = max(0.0, (v.bytes_sent - prev[1]) / dt)
            if d > 0 or u > 0 or tun:
                nics.append(NicRate(name=name, down_mo_s=round(d / 1e6, 3), up_mo_s=round(u / 1e6, 3), is_tunnel=tun))
        nics.sort(key=lambda n: n.down_mo_s + n.up_mo_s, reverse=True)

        note = ""
        if tunnel_present:
            note = ("Adaptateur VPN/tunnel détecté : son trafic peut être sous-compté par l'OS "
                    "(WireGuard/WinTun) — pour un débit exact, active la capture pktmon (admin).")

        self._last = (io.bytes_recv, io.bytes_sent)
        self._last_t = now
        return Bandwidth(down_bps=down, up_bps=up, down_mo_s=down / 1e6, up_mo_s=up / 1e6, nics=nics, note=note)
