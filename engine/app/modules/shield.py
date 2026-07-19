"""Module Bouclier : connexions réseau actives de la machine (psutil).

Données 100 % réelles : process (PID → nom/exe), lignée parent-enfant, IP/port distant,
DNS inverse. Aucune donnée inventée ; dégradation gracieuse si un process est protégé.
"""
from __future__ import annotations

import ipaddress
import socket
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import psutil
from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


class Connection(BaseModel):
    pid: int | None
    process: str
    exe: str = ""
    lineage: str = ""
    local_addr: str = ""
    remote_addr: str
    remote_dns: str | None = None
    dns_resolved: bool = False  # True = DNS résolu (nom ou None) ; False = pas encore résolu
    port: int
    protocol: str
    status: str


class TopTalker(BaseModel):
    pid: int
    process: str
    connections: int


class ShieldModule(Module):
    name = "shield"
    version = "0.1.0"
    description = "Connexions réseau live (psutil)"
    produces = ["connections"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._dns_cache: dict[str, str | None] = {}
        self._dns_pending: set[str] = set()
        self._executor: ThreadPoolExecutor | None = None

    def start(self) -> None:
        # Vérifie que psutil peut lire les connexions sur cette plateforme.
        psutil.net_connections(kind="inet")
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="red-dns")
        self.set_status(ModuleStatus.ACTIVE)

    def stop(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
        super().stop()

    # -- process / lignée ------------------------------------------------
    def _proc_info(self, pid: int | None, cache: dict[int, dict]) -> dict:
        if pid is None:
            return {"name": "?", "exe": "", "ppid": None}
        if pid in cache:
            return cache[pid]
        info = {"name": "?", "exe": "", "ppid": None}
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                info["name"] = proc.name()
                try:
                    info["exe"] = proc.exe()
                except (psutil.AccessDenied, psutil.Error):
                    info["exe"] = ""
                try:
                    info["ppid"] = proc.ppid()
                except psutil.Error:
                    info["ppid"] = None
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
            pass
        cache[pid] = info
        return info

    def _lineage(self, pid: int | None, cache: dict[int, dict], depth: int = 4) -> str:
        chain: list[str] = []
        current = pid
        seen: set[int] = set()
        while current and current not in seen and depth > 0:
            seen.add(current)
            info = self._proc_info(current, cache)
            chain.append(info["name"])
            current = info["ppid"]
            depth -= 1
        return " → ".join(reversed(chain))

    def process_tree(self, pid: int) -> str:
        """Lignée parent → enfant d'un PID (arbre de processus)."""
        return self._lineage(pid, {})

    # -- DNS inverse (résolu en arrière-plan pour ne pas bloquer l'endpoint) ----
    def _resolve_task(self, ip: str) -> None:
        try:
            name: str | None = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            name = None
        self._dns_cache[ip] = name
        self._dns_pending.discard(ip)

    def _rdns(self, ip: str) -> str | None:
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        if self._executor is not None and ip not in self._dns_pending:
            self._dns_pending.add(ip)
            self._executor.submit(self._resolve_task, ip)
        return None  # pas encore résolu ; sera disponible aux prochains appels

    # -- connexions ------------------------------------------------------
    def get_connections(self, resolve_dns: bool = True) -> list[Connection]:
        conns: list[Connection] = []
        cache: dict[int, dict] = {}
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr:  # on ne garde que les connexions avec un endpoint distant
                continue
            if _is_loopback(c.raddr.ip):  # on ignore le trafic loopback (bruit)
                continue
            info = self._proc_info(c.pid, cache)
            protocol = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            remote_ip = c.raddr.ip
            if resolve_dns:
                resolved = remote_ip in self._dns_cache
                dns = self._dns_cache.get(remote_ip)
                if not resolved:
                    self._rdns(remote_ip)  # planifie la résolution en arrière-plan
            else:
                resolved, dns = False, None
            conns.append(
                Connection(
                    pid=c.pid,
                    process=info["name"],
                    exe=info["exe"],
                    lineage=self._lineage(c.pid, cache) if c.pid else "",
                    local_addr=f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    remote_addr=remote_ip,
                    remote_dns=dns,
                    dns_resolved=resolved,
                    port=c.raddr.port,
                    protocol=protocol,
                    status=c.status,
                )
            )
        return conns

    def top_talkers(self) -> list[TopTalker]:
        """Process avec le plus de connexions actives (proxy réel de sollicitation)."""
        cache: dict[int, dict] = {}
        counter: Counter[int] = Counter()
        names: dict[int, str] = {}
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr or not c.pid or _is_loopback(c.raddr.ip):
                continue
            counter[c.pid] += 1
            if c.pid not in names:
                names[c.pid] = self._proc_info(c.pid, cache)["name"]
        return [
            TopTalker(pid=pid, process=names[pid], connections=n)
            for pid, n in counter.most_common(8)
        ]
