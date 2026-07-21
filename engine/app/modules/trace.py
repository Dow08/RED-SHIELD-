"""Module Traceroute géolocalisé — 100 % local (tracert/traceroute + base GeoIP hors-ligne).

Trace le chemin réseau jusqu'à une cible, géolocalise chaque saut via la base DB-IP
embarquée (aucune API externe), détecte un VPN actif (adaptateur), et déduit l'IP publique.
Exécution en tâche de fond (tracert est lent) avec cache.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import sys
import threading

from pydantic import BaseModel

from app.core import proc
from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

try:
    import maxminddb
except Exception:  # pragma: no cover
    maxminddb = None

_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_GEO_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "dbip-city-lite.mmdb"))


def _is_ipv4(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class Hop(BaseModel):
    hop: int
    ip: str
    dns: str | None = None
    city: str | None = None
    country: str | None = None
    lat: float | None = None
    lon: float | None = None
    private: bool = False


class TraceResult(BaseModel):
    target: str
    hops: list[Hop] = []
    public_ip: str | None = None
    vpn_active: bool = False
    vpn_adapter: str | None = None
    geo_available: bool = False
    running: bool = False
    error: str | None = None


class TraceModule(Module):
    name = "trace"
    version = "0.1.0"
    description = "Traceroute géolocalisé (hors-ligne)"
    produces = ["trace"]

    def __init__(self, bus: EventBus, geo_path: str | None = None) -> None:
        super().__init__(bus)
        self._geo_path = geo_path or _GEO_PATH
        self._geo = None
        self._cache: dict[str, TraceResult] = {}
        self._running: set[str] = set()
        self._lock = threading.Lock()
        self.default_target = "1.1.1.1"

    def start(self) -> None:
        if maxminddb is not None and os.path.exists(self._geo_path):
            try:
                self._geo = maxminddb.open_database(self._geo_path)
            except Exception:
                self._geo = None
        self.set_status(ModuleStatus.ACTIVE)
        # Le tracé se déclenche à la première requête (get), pas au démarrage.

    def stop(self) -> None:
        if self._geo is not None:
            try:
                self._geo.close()
            except Exception:
                pass
            self._geo = None
        super().stop()

    @property
    def geo_available(self) -> bool:
        return self._geo is not None

    def geo_lookup_fn(self):
        """Accès public à la fonction de géoloc hors-ligne (ou None) — évite aux
        consommateurs (main.py) de toucher aux attributs privés du module."""
        return self._geo_lookup if self.geo_available else None

    # -- détection VPN via les adaptateurs réseau -------------------------
    def detect_vpn(self) -> tuple[bool, str | None]:
        try:
            import psutil
            stats = psutil.net_if_stats()
        except Exception:
            return (False, None)
        for name, st in stats.items():
            if not getattr(st, "isup", False):
                continue
            low = name.lower()
            if any(k in low for k in ("nord", "tun", "tap", "wireguard", "wg", "vpn", "proton", "mullvad", "openvpn")):
                return (True, name)
        return (False, None)

    def _geo_lookup(self, ip: str) -> dict:
        if self._geo is None:
            return {}
        try:
            d = self._geo.get(ip)
        except Exception:
            return {}
        if not isinstance(d, dict):
            return {}
        loc = d.get("location", {}) or {}
        country = ((d.get("country", {}) or {}).get("names", {}) or {}).get("en")
        city = ((d.get("city", {}) or {}).get("names", {}) or {}).get("en")
        return {"lat": loc.get("latitude"), "lon": loc.get("longitude"), "city": city, "country": country}

    def _rdns(self, ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None

    @staticmethod
    def valid_target(target: str) -> bool:
        return bool(re.match(r"^[A-Za-z0-9_.\-]{1,255}$", target))

    def _cmd(self, target: str) -> list[str]:
        if sys.platform.startswith("win"):
            return ["tracert", "-d", "-h", "20", "-w", "700", target]
        return ["traceroute", "-n", "-m", "20", "-w", "2", target]

    def parse(self, output: str) -> list[Hop]:
        hops: list[Hop] = []
        for line in output.splitlines():
            m = re.match(r"\s*(\d+)\s", line)
            ips = _IPV4.findall(line)
            if not m or not ips:
                continue
            ip = ips[-1]
            if not _is_ipv4(ip):
                continue
            priv = _is_private(ip)
            geo = {} if priv else self._geo_lookup(ip)
            hops.append(
                Hop(
                    hop=int(m.group(1)),
                    ip=ip,
                    dns=self._rdns(ip),
                    city=geo.get("city"),
                    country=geo.get("country"),
                    lat=geo.get("lat"),
                    lon=geo.get("lon"),
                    private=priv,
                )
            )
        return hops

    def _run(self, target: str) -> None:
        with self._lock:
            self._cache[target] = TraceResult(target=target, geo_available=self.geo_available, running=True)
        ok, stdout, err = proc.run(self._cmd(target), timeout=90)
        if ok or stdout:
            hops = self.parse(stdout or "")
            vpn_active, vpn_adapter = self.detect_vpn()
            public = next((h.ip for h in hops if not h.private), None)
            result = TraceResult(target=target, hops=hops, public_ip=public, vpn_active=vpn_active,
                                 vpn_adapter=vpn_adapter, geo_available=self.geo_available, running=False)
        else:
            msg = "tracert introuvable" if err == "exécutable introuvable" else (err or "échec")
            result = TraceResult(target=target, geo_available=self.geo_available, running=False, error=msg)
        with self._lock:
            self._cache[target] = result
            self._running.discard(target)

    def run_async(self, target: str) -> None:
        if not self.valid_target(target):
            return
        with self._lock:
            if target in self._running:
                return
            self._running.add(target)
        threading.Thread(target=self._run, args=(target,), daemon=True).start()

    def get(self, target: str | None = None) -> TraceResult:
        target = target or self.default_target
        if not self.valid_target(target):
            return TraceResult(target=target, running=False, error="cible invalide")
        with self._lock:
            cached = self._cache.get(target)
        if cached is None:
            self.run_async(target)
            return TraceResult(target=target, running=True, geo_available=self.geo_available)
        return cached
