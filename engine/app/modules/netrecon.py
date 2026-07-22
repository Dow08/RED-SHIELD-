"""Recon réseau natif — portable, SANS nmap (approche mobile prototypée sur desktop).

Découverte d'hôtes (TCP connect + SSDP/UPnP + DNS inverse), scan de ports, empreinte de
services (bannières), énumération web (façon ffuf/gobuster) et audit TLS — le tout en
sockets/httpx purs. Aucune dépendance externe (nmap non requis) → **exactement la logique
que le futur plugin natif mobile** portera en Rust.

⚠️ Action ACTIVE (connexions vers la cible) : à n'utiliser que sur une cible autorisée.
Le garde-fou de périmètre (côté API/UI) journalise tout scan hors périmètre.
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import socket
import ssl
from datetime import datetime, timezone

from pydantic import BaseModel

from app.core import http
from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

# Ports « signe de vie » pour la découverte (peu nombreux → rapide).
_DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 8080, 139, 53]
# Top ports pour le scan d'un hôte (services courants LAN + web + admin).
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 515, 548,
             587, 631, 993, 995, 1433, 1521, 1723, 2049, 2082, 2083, 3000, 3128, 3306,
             3389, 5000, 5060, 5432, 5900, 5985, 6379, 7547, 8000, 8008, 8009, 8080,
             8081, 8443, 8888, 9000, 9100, 9200, 27017, 62078]
_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 515: "printer", 548: "afp", 587: "smtp", 631: "ipp", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 5985: "winrm", 6379: "redis", 7547: "cwmp",
    8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 9100: "jetdirect", 9200: "elastic",
    27017: "mongodb", 62078: "apple-sync",
}
_HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 3000, 5000, 8888, 9200, 2082, 3128, 631}
_TLS_PORTS = {443, 8443, 993, 995, 465, 5985}


def _service(port: int) -> str:
    return _SERVICE_NAMES.get(port, "")


class HostR(BaseModel):
    ip: str
    hostname: str = ""
    open_ports: list[int] = []
    device: str = ""            # nom/modèle exposé via SSDP/UPnP
    source: str = "tcp"         # tcp / ssdp


class PortR(BaseModel):
    port: int
    proto: str = "tcp"
    service: str = ""
    product: str = ""
    banner: str = ""


class WebFinding(BaseModel):
    path: str
    status: int
    size: int = 0
    kind: str = "dir"           # dir / vhost


class TlsInfo(BaseModel):
    host: str
    port: int
    ok: bool = False
    issuer: str = ""
    subject: str = ""
    not_after: str = ""
    protocol: str = ""
    cipher: str = ""
    weak: list[str] = []
    error: str = ""


# ── primitives réseau ─────────────────────────────────────────────────────
def _tcp_open(ip: str, port: int, timeout: float = 0.35) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def _grab_banner(ip: str, port: int, timeout: float = 1.2) -> tuple[str, str]:
    """Renvoie (banner, product). HTTP → en-tête Server ; sinon bannière brute."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return "", ""
            if port in _HTTP_PORTS:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
            data = s.recv(1024)
    except OSError:
        return "", ""
    text = data.decode("utf-8", "replace").strip()
    product = ""
    for line in text.splitlines():
        low = line.lower()
        if low.startswith("server:"):
            product = line.split(":", 1)[1].strip()
            break
    return text[:300], product


# ── SSDP / UPnP (identifie box/IoT/imprimantes sans root) ──────────────────
def _ssdp_probe(timeout: float = 2.0) -> dict[str, str]:
    """M-SEARCH SSDP multicast → {ip: description serveur}. Silencieux si indisponible."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n').encode()
    found: dict[str, str] = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        s.sendto(msg, ("239.255.255.250", 1900))
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            except OSError:
                break
            ip = addr[0]
            desc = ""
            for line in data.decode("utf-8", "replace").splitlines():
                low = line.lower()
                if low.startswith("server:"):
                    desc = line.split(":", 1)[1].strip()
            found.setdefault(ip, desc)
        s.close()
    except OSError:
        return {}
    return found


# ── API du moteur ─────────────────────────────────────────────────────────
def parse_targets(cidr: str) -> list[str]:
    """CIDR / IP / plage → liste d'IP (plafonnée à 512 pour rester rapide et sûr)."""
    cidr = (cidr or "").strip()
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        try:
            ip = ipaddress.ip_address(cidr)
            return [str(ip)]
        except ValueError:
            return []
    ips = [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    return ips[:512]


def discover_hosts(cidr: str, timeout: float = 0.35, workers: int = 128) -> list[HostR]:
    ips = parse_targets(cidr)
    if not ips:
        return []
    ssdp = _ssdp_probe() if len(ips) > 1 else {}

    def probe(ip: str):
        opens = []
        for p in _DISCOVERY_PORTS:
            if _tcp_open(ip, p, timeout):
                opens.append(p)
        alive = bool(opens) or ip in ssdp
        return (ip, opens) if alive else None

    alive: dict[str, list[int]] = {}
    with cf.ThreadPoolExecutor(max_workers=min(workers, max(1, len(ips)))) as ex:
        for res in ex.map(probe, ips):
            if res:
                alive[res[0]] = res[1]
    out = []
    for ip in sorted(alive, key=lambda x: ipaddress.ip_address(x)):
        out.append(HostR(ip=ip, hostname=_rdns(ip), open_ports=alive[ip],
                         device=ssdp.get(ip, ""), source="ssdp" if ip in ssdp else "tcp"))
    return out


def scan_ports(ip: str, ports: list[int] | None = None, timeout: float = 0.4,
               workers: int = 200, fingerprint: bool = True) -> list[PortR]:
    ports = ports or TOP_PORTS
    open_ports: list[int] = []
    with cf.ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports)))) as ex:
        results = ex.map(lambda p: (p, _tcp_open(ip, p, timeout)), ports)
        open_ports = [p for p, ok in results if ok]
    out = []
    for p in sorted(open_ports):
        banner, product = ("", "")
        if fingerprint:
            banner, product = _grab_banner(ip, p)
        out.append(PortR(port=p, service=_service(p), product=product, banner=banner))
    return out


def web_enum(base_url: str, words: list[str] | None = None, timeout: float = 4.0,
             workers: int = 24) -> list[WebFinding]:
    """Fuzz de répertoires (façon gobuster/ffuf). base_url = http(s)://host[:port]."""
    base = (base_url or "").rstrip("/")
    if not base.startswith("http"):
        base = "http://" + base
    words = words or DEFAULT_WORDLIST
    # Détection 404 fiable : on teste un chemin aléatoire improbable.
    ref = http.get(base + "/red-shield-404-probe-zzz", timeout=timeout, local=True)
    ref_status = ref.status_code

    def one(w: str):
        w = w.strip().strip("/")
        if not w:
            return None
        r = http.get(f"{base}/{w}", timeout=timeout, local=True)
        if r.error or r.status_code == 0:
            return None
        # « trouvé » = status différent d'un 404 franc (ou du status de la sonde 404).
        if r.status_code in (404,) or (ref_status not in (0, 404) and r.status_code == ref_status):
            return None
        return WebFinding(path="/" + w, status=r.status_code, size=len(r.text or ""))

    out: list[WebFinding] = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(one, words):
            if res:
                out.append(res)
    out.sort(key=lambda f: (f.status, f.path))
    return out[:200]


def tls_audit(host: str, port: int = 443, timeout: float = 4.0) -> TlsInfo:
    info = TlsInfo(host=host, port=port)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE           # lab / auto-signé : on inspecte, on ne valide pas
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                info.protocol = ss.version() or ""
                ci = ss.cipher()
                info.cipher = ci[0] if ci else ""
        info.ok = True
    except Exception as exc:
        info.error = str(exc)
        return info
    if cert:
        info.issuer = _name(cert.get("issuer"))
        info.subject = _name(cert.get("subject"))
        info.not_after = cert.get("notAfter", "")
    # Faiblesses
    if info.protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        info.weak.append(f"protocole obsolète {info.protocol}")
    if any(x in info.cipher.upper() for x in ("RC4", "3DES", "DES", "NULL", "MD5", "EXPORT")):
        info.weak.append(f"chiffrement faible {info.cipher}")
    if info.not_after:
        try:
            exp = datetime.strptime(info.not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                info.weak.append("certificat expiré")
        except ValueError:
            pass
    return info


def _name(rdn) -> str:
    if not rdn:
        return ""
    parts = []
    for tup in rdn:
        for k, v in tup:
            if k in ("commonName", "organizationName"):
                parts.append(v)
    return " / ".join(parts)


# Petite wordlist embarquée (répertoires/fichiers courants). Extensible.
DEFAULT_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin", "dashboard",
    "api", "api/v1", "config", "config.php", ".env", ".git", ".git/config", "backup", "backups",
    "db", "database", "sql", "dump.sql", "test", "dev", "staging", "old", "tmp", "temp",
    "uploads", "files", "images", "assets", "static", "js", "css", "includes", "vendor",
    "server-status", "server-info", "robots.txt", "sitemap.xml", ".htaccess", "web.config",
    "console", "manager", "manager/html", "actuator", "actuator/health", "metrics", "status",
    "swagger", "swagger-ui.html", "graphql", "user", "users", "account", "portal", "cgi-bin",
    "webdav", "owa", "remote", "vpn", "cpanel", "webmail", "monitoring", "grafana", "kibana",
]


class NetreconModule(Module):
    name = "netrecon"
    version = "0.1.0"
    description = "Recon réseau natif (sans nmap) — cartographie, énum web, TLS"

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    def discover(self, cidr: str) -> list[HostR]:
        return discover_hosts(cidr)

    def ports(self, ip: str) -> list[PortR]:
        return scan_ports(ip)

    def web(self, base_url: str) -> list[WebFinding]:
        return web_enum(base_url)

    def tls(self, host: str, port: int = 443) -> TlsInfo:
        return tls_audit(host, port)

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
