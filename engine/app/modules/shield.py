"""Module Bouclier : connexions réseau actives de la machine (psutil).

Données 100 % réelles : process (PID → nom/exe), lignée parent-enfant, IP/port distant,
DNS inverse. Aucune donnée inventée ; dégradation gracieuse si un process est protégé.
"""
from __future__ import annotations

import ipaddress
import queue
import socket
import threading
from collections import Counter

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
    direction: str = "sortant"  # "entrant" (vers un port en écoute local) ou "sortant"


class Listener(BaseModel):
    """Port en écoute = point d'entrée potentiel (surface d'exposition entrante)."""
    pid: int | None
    process: str
    exe: str = ""
    addr: str = ""       # IP de liaison locale
    port: int
    protocol: str
    exposed: bool        # True = liée à 0.0.0.0/:: ou une IP réseau (joignable depuis le LAN/WAN)


class PortCount(BaseModel):
    port: int
    count: int
    service: str = ""
    encrypted: bool = False


class KeyCount(BaseModel):
    key: str
    count: int


class CountryStat(BaseModel):
    key: str
    count: int
    processes: list[KeyCount] = []   # applications à l'origine des connexions vers ce pays


class NetMetrics(BaseModel):
    total: int = 0
    inbound: int = 0
    outbound: int = 0
    tcp: int = 0
    udp: int = 0            # UDP avec destinataire connu (rare : psutil est sans-connexion pour l'UDP)
    udp_sockets: int = 0    # sockets UDP actifs (réel) — le flux/destinataire nécessite la capture pktmon
    encrypted: int = 0
    clear: int = 0
    endpoints: int = 0
    listeners: int = 0
    listeners_exposed: int = 0
    countries: list[CountryStat] = []
    top_ports: list[PortCount] = []
    tcp_ports: list[PortCount] = []
    udp_ports: list[PortCount] = []


class TopTalker(BaseModel):
    pid: int
    process: str
    connections: int


class GeoPoint(BaseModel):
    ip: str
    dns: str = ""
    lat: float
    lon: float
    country: str = ""
    city: str = ""
    process: str = ""
    count: int = 1
    severity: str = "safe"
    direction: str = "sortant"   # entrant / sortant (pour tracer les flux)


class GeoView(BaseModel):
    home: GeoPoint | None = None   # point de sortie (géoloc de l'IP publique de la box)
    points: list[GeoPoint] = []


_SEV_RANK = {"safe": 0, "watch": 1, "suspect": 2, "crit": 3}


# Ports chiffrés courants (transport TLS/SSH/…) — pour le ratio chiffré/clair.
_ENCRYPTED_PORTS = {22, 443, 465, 563, 636, 853, 989, 990, 993, 995, 5061, 6697, 8443}
# Libellés de services courants (indicatif, pour l'affichage des top ports).
_PORT_SERVICE = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 123: "ntp", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 587: "smtp", 636: "ldaps", 853: "dns-tls",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5672: "amqp", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elastic", 27017: "mongodb",
}


class ShieldModule(Module):
    name = "shield"
    version = "0.1.0"
    description = "Connexions réseau live (psutil)"
    produces = ["connections"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._dns_cache: dict[str, str | None] = {}
        self._dns_pending: set[str] = set()
        self._dns_queue: "queue.Queue[str]" = queue.Queue()
        self._dns_stop = threading.Event()
        self._dns_workers: list[threading.Thread] = []

    def start(self) -> None:
        # Vérifie que psutil peut lire les connexions sur cette plateforme.
        psutil.net_connections(kind="inet")
        # Résolution DNS via threads DAEMON (ne bloquent pas la sortie du process).
        self._dns_stop.clear()
        self._dns_workers = [threading.Thread(target=self._dns_worker, daemon=True) for _ in range(4)]
        for t in self._dns_workers:
            t.start()
        self.set_status(ModuleStatus.ACTIVE)

    def stop(self) -> None:
        self._dns_stop.set()
        super().stop()

    def _dns_worker(self) -> None:
        while not self._dns_stop.is_set():
            try:
                ip = self._dns_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                name: str | None = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                name = None
            self._dns_cache[ip] = name
            self._dns_pending.discard(ip)

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
    def _rdns(self, ip: str) -> str | None:
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        if ip not in self._dns_pending:
            self._dns_pending.add(ip)
            self._dns_queue.put(ip)
        return None  # pas encore résolu ; sera disponible aux prochains appels

    @staticmethod
    def _listen_ports(raw: list) -> set[int]:
        """Ports locaux en écoute (servent à distinguer les connexions entrantes)."""
        return {c.laddr.port for c in raw if c.status == psutil.CONN_LISTEN and c.laddr}

    # -- connexions ------------------------------------------------------
    def get_connections(self, resolve_dns: bool = True) -> list[Connection]:
        conns: list[Connection] = []
        cache: dict[int, dict] = {}
        raw = psutil.net_connections(kind="inet")
        listen_ports = self._listen_ports(raw)
        for c in raw:
            if not c.raddr:  # on ne garde que les connexions avec un endpoint distant
                continue
            if _is_loopback(c.raddr.ip):  # on ignore le trafic loopback (bruit)
                continue
            info = self._proc_info(c.pid, cache)
            protocol = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            remote_ip = c.raddr.ip
            # Entrant = le port local est un port en écoute (un tiers s'est connecté à nous).
            direction = "entrant" if (c.laddr and c.laddr.port in listen_ports) else "sortant"
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
                    direction=direction,
                )
            )
        return conns

    # -- ports en écoute (surface d'exposition entrante) -----------------
    def get_listeners(self) -> list[Listener]:
        cache: dict[int, dict] = {}
        seen: dict[tuple[int, str], Listener] = {}
        for c in psutil.net_connections(kind="inet"):
            if c.status != psutil.CONN_LISTEN or not c.laddr:
                continue
            info = self._proc_info(c.pid, cache)
            ip = c.laddr.ip
            protocol = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            exposed = not _is_loopback(ip)  # 127.0.0.1/::1 = local seulement
            key = (c.laddr.port, protocol)
            prev = seen.get(key)
            if prev is None:
                seen[key] = Listener(pid=c.pid, process=info["name"], exe=info["exe"],
                                     addr=ip, port=c.laddr.port, protocol=protocol, exposed=exposed)
            elif exposed and not prev.exposed:  # IPv4+IPv6 : on retient la variante exposée
                prev.exposed = True
                prev.addr = ip
        return sorted(seen.values(), key=lambda l: (not l.exposed, l.port))

    # -- métriques réseau agrégées (dashboard) ---------------------------
    def metrics(self, geo=None) -> NetMetrics:
        """Agrège les connexions réelles en indicateurs de surveillance.

        `geo` (optionnel) : fonction ip -> {"country": str|None} pour compter les
        pays distincts hors-ligne (injectée depuis le module trace).
        """
        raw = psutil.net_connections(kind="inet")
        listen_ports = self._listen_ports(raw)
        m = NetMetrics()
        cache: dict[int, dict] = {}
        ports: Counter[int] = Counter()
        tcp_ports: Counter[int] = Counter()
        udp_ports: Counter[int] = Counter()
        countries: Counter[str] = Counter()
        country_procs: dict[str, Counter] = {}
        endpoints: set[str] = set()
        # Sockets UDP actifs (réels) : psutil ne fournit pas leur destinataire (sans-connexion),
        # mais leur présence prouve qu'il y a du trafic UDP (QUIC/vidéo…) — flux exact via pktmon.
        m.udp_sockets = sum(1 for c in raw if c.type == socket.SOCK_DGRAM and c.laddr and not _is_loopback(c.laddr.ip))
        for c in raw:
            if not c.raddr or _is_loopback(c.raddr.ip):
                continue
            m.total += 1
            if c.laddr and c.laddr.port in listen_ports:
                m.inbound += 1
            else:
                m.outbound += 1
            if c.type == socket.SOCK_STREAM:
                m.tcp += 1
                tcp_ports[c.raddr.port] += 1
            else:
                m.udp += 1
                udp_ports[c.raddr.port] += 1
            if c.raddr.port in _ENCRYPTED_PORTS:
                m.encrypted += 1
            else:
                m.clear += 1
            ports[c.raddr.port] += 1
            endpoints.add(c.raddr.ip)
            if geo is not None:
                try:
                    g = geo(c.raddr.ip)
                except Exception:
                    g = None
                if g and g.get("country"):
                    country = g["country"]
                    countries[country] += 1
                    proc = self._proc_info(c.pid, cache)["name"] if c.pid else "?"
                    country_procs.setdefault(country, Counter())[proc] += 1
        m.endpoints = len(endpoints)
        listeners = self.get_listeners()
        m.listeners = len(listeners)
        m.listeners_exposed = sum(1 for l in listeners if l.exposed)
        m.countries = [
            CountryStat(key=k, count=n,
                        processes=[KeyCount(key=pk, count=pn) for pk, pn in country_procs.get(k, Counter()).most_common(5)])
            for k, n in countries.most_common(6)
        ]
        def _mk(counter: Counter, k: int = 6) -> list[PortCount]:
            return [
                PortCount(port=p, count=n, service=_PORT_SERVICE.get(p, ""), encrypted=p in _ENCRYPTED_PORTS)
                for p, n in counter.most_common(k)
            ]
        m.top_ports = _mk(ports)
        m.tcp_ports = _mk(tcp_ports, 8)
        m.udp_ports = _mk(udp_ports, 8)
        return m

    def geo_points(self, scored: list, geo) -> list[GeoPoint]:
        """Points géolocalisés des connexions distantes publiques (pour la mappemonde).

        Agrège par IP : position (lat/lon via geo hors-ligne), process représentatif,
        nombre de connexions, sévérité maximale. `scored` = connexions notées.
        """
        if geo is None:
            return []
        agg: dict[str, dict] = {}
        for c in scored:
            ip = c.remote_addr
            try:
                ipa = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ipa.is_loopback or ipa.is_private:
                continue
            try:
                g = geo(ip)
            except Exception:
                g = None
            if not g or g.get("lat") is None or g.get("lon") is None:
                continue
            sev = getattr(c, "severity", "safe")
            dns = getattr(c, "remote_dns", "") or ""
            direction = getattr(c, "direction", "sortant")
            e = agg.get(ip)
            if e is None:
                agg[ip] = {"ip": ip, "dns": dns, "lat": g["lat"], "lon": g["lon"], "country": g.get("country") or "",
                           "city": g.get("city") or "", "process": c.process, "count": 1, "sev": sev, "dir": direction}
            else:
                e["count"] += 1
                if dns and not e["dns"]:
                    e["dns"] = dns
                if direction == "entrant":
                    e["dir"] = "entrant"
                if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(e["sev"], 0):
                    e["sev"] = sev
                    e["process"] = c.process
        return [GeoPoint(ip=e["ip"], dns=e["dns"], lat=e["lat"], lon=e["lon"], country=e["country"], city=e["city"],
                         process=e["process"], count=e["count"], severity=e["sev"], direction=e["dir"]) for e in agg.values()]

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
