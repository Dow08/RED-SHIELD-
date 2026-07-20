"""Module Débit par processus + capture entrante — via pktmon (intégré à Windows).

Capture les paquets en temps réel (`pktmon start --capture --log-mode real-time`,
aucun fichier créé), attribue chaque paquet à un PID en croisant le 5-tuple avec
les connexions psutil, et en déduit le **débit réel par processus** (↓/↑) ainsi
qu'un **compteur de paquets entrants** (surveillance de la surface d'exposition).

Contraintes assumées :
- Windows uniquement, **droits administrateur requis** (pktmon = pilote noyau).
- Sans admin / hors Windows / pktmon absent → module en état dégradé, message clair,
  aucune donnée inventée. L'UI retombe sur le proxy « nombre de connexions ».
- Parseur `parse_realtime_line` isolé et testé unitairement (formats tolérés).
"""
from __future__ import annotations

import re
import subprocess
import sys
import threading
import time

import psutil
from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

_IPV4 = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
# Endpoints "ip:port" ou "ip.port" (pktmon écrit parfois l'IPv4 suffixée du port par un point).
_ENDPOINT = re.compile(rf"({_IPV4})[:.](\d{{1,5}})\b")
# Format verbeux (etl2txt) : "SourceAddress 1.2.3.4 ... SourcePort 49764 ..."
_SRC_IP = re.compile(rf"Source(?:Address)?\s*[:=]?\s*({_IPV4})", re.IGNORECASE)
_DST_IP = re.compile(rf"Dest(?:ination)?(?:Address)?\s*[:=]?\s*({_IPV4})", re.IGNORECASE)
_SRC_PORT = re.compile(r"Source\s?Port\s*[:=]?\s*(\d{1,5})", re.IGNORECASE)
_DST_PORT = re.compile(r"Dest(?:ination)?\s?Port\s*[:=]?\s*(\d{1,5})", re.IGNORECASE)
_LEN = re.compile(r"(?:Len|Length|Total Length\s*=?)\s*[:=]?\s*(\d+)", re.IGNORECASE)
_DIR_RX = re.compile(r"\b(Rx|Receive|Inbound|Ingress)\b", re.IGNORECASE)
_DIR_TX = re.compile(r"\b(Tx|Send|Transmit|Outbound|Egress)\b", re.IGNORECASE)
_PROTO = re.compile(r"\b(TCP|UDP)\b", re.IGNORECASE)

WINDOW_S = 3.0  # fenêtre glissante pour le calcul du débit


def is_admin() -> bool:
    """Vrai si le process courant est élevé (admin) — nécessaire à pktmon."""
    if not sys.platform.startswith("win"):
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def parse_realtime_line(line: str) -> dict | None:
    """Extrait {direction, proto, endpoints:[(ip,port),...], length} d'une ligne pktmon.

    Tolérant aux variations de format (real-time / etl2txt). Renvoie None si la ligne
    ne décrit pas un paquet IP exploitable.
    """
    if not line or ("TCP" not in line and "UDP" not in line and "." not in line):
        return None
    endpoints = [(ip, int(port)) for ip, port in _ENDPOINT.findall(line) if int(port) <= 65535]
    if len(endpoints) < 2:
        # Repli sur le format verbeux (adresses/ports séparés).
        sip, dip = _SRC_IP.search(line), _DST_IP.search(line)
        sp, dp = _SRC_PORT.search(line), _DST_PORT.search(line)
        if sip and dip and sp and dp:
            endpoints = [(sip.group(1), int(sp.group(1))), (dip.group(1), int(dp.group(1)))]
        else:
            return None
    proto_m = _PROTO.search(line)
    len_m = _LEN.search(line)
    # Direction : Rx = entrant (reçu), Tx = sortant (émis). Défaut : inconnu.
    if _DIR_RX.search(line):
        direction = "rx"
    elif _DIR_TX.search(line):
        direction = "tx"
    else:
        direction = "?"
    return {
        "direction": direction,
        "proto": (proto_m.group(1).lower() if proto_m else ""),
        "endpoints": endpoints[:2],
        "length": int(len_m.group(1)) if len_m else 0,
    }


class ProcThroughput(BaseModel):
    pid: int
    process: str
    down_bps: float = 0.0
    up_bps: float = 0.0
    down_mo_s: float = 0.0
    up_mo_s: float = 0.0


class ThroughputStatus(BaseModel):
    available: bool = False      # capture active et exploitable
    admin: bool = False
    platform_ok: bool = False
    pktmon_present: bool = False
    capturing: bool = False
    reason: str = ""
    inbound_packets: int = 0     # paquets entrants observés depuis le démarrage
    packets_seen: int = 0


class ThroughputModule(Module):
    name = "throughput"
    version = "0.1.0"
    description = "Débit par processus + capture entrante (pktmon)"
    produces = ["throughput"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._admin = False
        self._pktmon = False
        self._capturing = False
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._map_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        # samples[pid] = list[(ts, down_bytes, up_bytes)]
        self._samples: dict[int, list[tuple[float, int, int]]] = {}
        self._names: dict[int, str] = {}
        self._portmap: dict[int, int] = {}      # port local -> pid
        self._inbound_packets = 0
        self._packets_seen = 0
        self._reason = ""

    # -- cycle de vie ----------------------------------------------------
    def start(self) -> None:
        self._admin = is_admin()
        self._pktmon = self._find_pktmon()
        plat = sys.platform.startswith("win")
        if not plat:
            self._degraded("capture disponible sur Windows uniquement (pktmon)")
            return
        if not self._pktmon:
            self._degraded("pktmon introuvable (composant Windows)")
            return
        if not self._admin:
            self._degraded("droits administrateur requis — relance RED en admin (run-admin.ps1)")
            return
        # Admin + pktmon : on lance la capture temps réel.
        self._stop.clear()
        self._map_thread = threading.Thread(target=self._refresh_portmap_loop, daemon=True)
        self._map_thread.start()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        self._capturing = True
        self.set_status(ModuleStatus.ACTIVE)

    def _degraded(self, reason: str) -> None:
        """État dégradé non bloquant : le module reste 'inactif' avec un message clair."""
        self._reason = reason
        self._capturing = False
        self.set_status(ModuleStatus.NOT_CONNECTED, reason)

    def stop(self) -> None:
        self._stop.set()
        self._capturing = False
        if self._proc is not None:
            try:
                self._proc.terminate()
            except Exception:
                pass
        if sys.platform.startswith("win") and self._admin and self._pktmon:
            try:
                subprocess.run(["pktmon", "stop"], capture_output=True, timeout=10)
            except Exception:
                pass
        super().stop()

    @staticmethod
    def _find_pktmon() -> bool:
        import shutil
        return shutil.which("pktmon") is not None

    # -- carte port local -> PID (rafraîchie en fond) --------------------
    def _refresh_portmap(self) -> None:
        portmap: dict[int, int] = {}
        names: dict[int, str] = {}
        for c in psutil.net_connections(kind="inet"):
            if c.laddr and c.pid:
                portmap[c.laddr.port] = c.pid
        with self._lock:
            self._portmap = portmap
            self._names.update(names)

    def _refresh_portmap_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._refresh_portmap()
            except Exception:
                pass
            self._stop.wait(2.0)

    def _pid_name(self, pid: int) -> str:
        if pid in self._names:
            return self._names[pid]
        try:
            name = psutil.Process(pid).name()
        except Exception:
            name = "?"
        self._names[pid] = name
        return name

    # -- capture temps réel ----------------------------------------------
    def _capture_cmd(self) -> list[str]:
        # real-time : streame les paquets à l'écran, aucun fichier créé.
        return ["pktmon", "start", "--capture", "--pkt-size", "0", "--log-mode", "real-time"]

    def _capture_loop(self) -> None:
        try:
            self._proc = subprocess.Popen(
                self._capture_cmd(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
        except Exception as exc:
            self._degraded(f"échec démarrage pktmon : {exc}")
            return
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            if self._stop.is_set():
                break
            self._ingest(line)

    def _ingest(self, line: str) -> None:
        pkt = parse_realtime_line(line)
        if pkt is None:
            return
        self._packets_seen += 1
        (ip_a, port_a), (ip_b, port_b) = pkt["endpoints"]
        # Le port local est celui présent dans la carte des connexions.
        with self._lock:
            pid = self._portmap.get(port_a) or self._portmap.get(port_b)
        if not pid:
            return
        down = up = 0
        if pkt["direction"] == "rx":
            down = pkt["length"]
            self._inbound_packets += 1
        elif pkt["direction"] == "tx":
            up = pkt["length"]
        else:
            # direction inconnue : on répartit selon quel endpoint est local
            if self._portmap.get(port_a):
                up = pkt["length"]
            else:
                down = pkt["length"]
        now = time.monotonic()
        with self._lock:
            buf = self._samples.setdefault(pid, [])
            buf.append((now, down, up))

    def _prune(self, now: float) -> None:
        cutoff = now - WINDOW_S
        for pid, buf in list(self._samples.items()):
            kept = [s for s in buf if s[0] >= cutoff]
            if kept:
                self._samples[pid] = kept
            else:
                del self._samples[pid]

    # -- lecture ---------------------------------------------------------
    def processes(self, top: int = 8) -> list[ProcThroughput]:
        now = time.monotonic()
        out: list[ProcThroughput] = []
        with self._lock:
            self._prune(now)
            for pid, buf in self._samples.items():
                down = sum(s[1] for s in buf)
                up = sum(s[2] for s in buf)
                dbps = down / WINDOW_S
                ubps = up / WINDOW_S
                out.append(ProcThroughput(
                    pid=pid, process=self._pid_name(pid),
                    down_bps=dbps, up_bps=ubps,
                    down_mo_s=round(dbps / 1_000_000, 3), up_mo_s=round(ubps / 1_000_000, 3),
                ))
        out.sort(key=lambda p: p.down_bps + p.up_bps, reverse=True)
        return out[:top]

    def status(self) -> ThroughputStatus:
        return ThroughputStatus(
            available=self._capturing,
            admin=self._admin,
            platform_ok=sys.platform.startswith("win"),
            pktmon_present=self._pktmon,
            capturing=self._capturing,
            reason=self._reason,
            inbound_packets=self._inbound_packets,
            packets_seen=self._packets_seen,
        )
