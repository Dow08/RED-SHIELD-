"""Module Scan (recon offensif) — nmap + croisement CVE local (offline).

Scanne une cible AUTORISÉE (ports/services/versions via nmap -sT -sV, sans privilège),
puis croise chaque service+version avec une base CVE locale curée → liens NVD.
Exécution en tâche de fond avec cache. Localise nmap même hors PATH.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET

from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

_NMAP_CANDIDATES = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]
_CVE_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "cve_local.json"))


def _find_nmap() -> str | None:
    found = shutil.which("nmap")
    if found:
        return found
    for path in _NMAP_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


class Cve(BaseModel):
    cve: str
    cvss: float
    severity: str
    summary: str
    url: str


class Compliance(BaseModel):
    framework: str
    control: str
    note: str


class Port(BaseModel):
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    cves: list[Cve] = []
    osi_layer: int = 7
    osi_label: str = "L7 Application"
    compliance: list[Compliance] = []
    suggestions: list[str] = []


# --- Décomposition OSI (par service/port) ---
_TLS_PORTS = {443, 8443, 993, 995, 465, 990, 636, 989, 5061}
_ENC_TOKENS = ("ssl", "tls", "https", "imaps", "pop3s", "smtps", "ldaps")


def _osi_of(port: int, service: str) -> tuple[int, str]:
    s = (service or "").lower()
    if port in _TLS_PORTS or any(tok in s for tok in _ENC_TOKENS):
        return (6, "L6 Présentation (TLS)")
    if not s:
        return (4, "L4 Transport")
    return (7, "L7 Application")


# --- Conformité (indicatif) : service → contrôles CIS/ANSSI/NIST ---
_COMPLIANCE: dict[str, list[dict]] = {
    "ftp": [{"framework": "ANSSI", "control": "BP-028 R41", "note": "FTP en clair — préférer SFTP/FTPS"}, {"framework": "CIS", "control": "CIS 2", "note": "désactiver les services non chiffrés"}],
    "telnet": [{"framework": "ANSSI", "control": "BP-028 R41", "note": "Telnet en clair — désactiver, utiliser SSH"}, {"framework": "NIST", "control": "PR.PT-4", "note": "protéger les communications"}],
    "microsoft-ds": [{"framework": "CIS", "control": "CIS 9", "note": "restreindre SMB au pare-feu, désactiver SMBv1"}, {"framework": "NIST", "control": "PR.AC-5", "note": "segmentation réseau"}],
    "netbios-ssn": [{"framework": "CIS", "control": "CIS 9", "note": "NetBIOS exposé — restreindre"}],
    "ms-wbt-server": [{"framework": "CIS", "control": "CIS 18", "note": "RDP : activer NLA, restreindre l'accès"}, {"framework": "ANSSI", "control": "BP-028", "note": "limiter l'exposition RDP"}],
    "http": [{"framework": "NIST", "control": "PR.DS-2", "note": "chiffrer les flux (HTTPS)"}],
    "ssh": [{"framework": "ANSSI", "control": "BP-028 R55", "note": "durcir SSH (clés, root interdit)"}],
    "smtp": [{"framework": "NIST", "control": "PR.DS-2", "note": "activer STARTTLS ; vérifier open relay"}],
    "mysql": [{"framework": "CIS", "control": "CIS 5", "note": "ne pas exposer la base ; comptes forts"}],
    "microsoft-sql-server": [{"framework": "CIS", "control": "CIS 5", "note": "ne pas exposer MSSQL ; auth forte"}],
}

# --- Suggestions d'attaque (esprit sk-recon) : service → pistes d'énumération ---
_SUGGEST: dict[str, list[str]] = {
    "http": ["feroxbuster / gobuster (énum. répertoires)", "nikto (vulns web)", "whatweb (fingerprint)"],
    "https": ["feroxbuster (HTTPS)", "sslscan / testssl.sh (config TLS)", "nikto"],
    "ssh": ["ssh-audit (durcissement)", "hydra ssh (brute-force si autorisé)"],
    "ftp": ["vérifier le login anonyme", "hydra ftp"],
    "microsoft-ds": ["enum4linux-ng", "netexec smb (shares/users)"],
    "netbios-ssn": ["enum4linux-ng", "nbtscan"],
    "ms-wbt-server": ["netexec rdp", "ncrack rdp (si autorisé)"],
    "msrpc": ["rpcdump (impacket)", "enum via impacket"],
    "domain": ["dnsenum", "dig AXFR (transfert de zone)"],
    "mysql": ["netexec mysql", "hydra mysql"],
    "microsoft-sql-server": ["netexec mssql", "mssqlclient (impacket)"],
    "smtp": ["smtp-user-enum", "test open relay"],
    "ldap": ["ldapsearch (anonymous bind)", "windapsearch"],
}


class Host(BaseModel):
    ip: str
    hostname: str = ""
    os: str = ""
    ports: list[Port] = []


class ScanResult(BaseModel):
    target: str = ""
    mode: str = "discret"
    hosts: list[Host] = []
    running: bool = False
    error: str | None = None
    nmap_available: bool = True


class ScanRequest(BaseModel):
    target: str
    mode: str = "discret"


class ScanModule(Module):
    name = "scan"
    version = "0.1.0"
    description = "Scan nmap + CVE (offline)"
    produces = ["scan"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._nmap: str | None = None
        self._cve: list[dict] = []
        self._last: ScanResult | None = None
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        self._nmap = _find_nmap()
        try:
            with open(_CVE_PATH, encoding="utf-8") as f:
                self._cve = json.load(f)
        except Exception:
            self._cve = []
        if self._nmap:
            self.set_status(ModuleStatus.ACTIVE)
        else:
            self.set_status(ModuleStatus.NOT_INSTALLED, "nmap non installé (voir A_INSTALLER)")

    @property
    def nmap_available(self) -> bool:
        return self._nmap is not None

    @staticmethod
    def valid_target(target: str) -> bool:
        return bool(re.match(r"^[A-Za-z0-9_.\-/]{1,64}$", target))

    def match_cves(self, product: str, version: str) -> list[Cve]:
        out: list[Cve] = []
        p = (product or "").lower()
        v = version or ""
        if not p or not v:
            return out
        for e in self._cve:
            if e["product"].lower() in p and any(v.startswith(tok) or v == tok for tok in e["versions"]):
                out.append(Cve(cve=e["cve"], cvss=e["cvss"], severity=e["severity"], summary=e["summary"], url=e["url"]))
        return out

    def parse(self, xml: str) -> list[Host]:
        root = ET.fromstring(xml)
        hosts: list[Host] = []
        for h in root.findall("host"):
            addr = h.find("address")
            ip = addr.get("addr") if addr is not None else ""
            hn_el = h.find("hostnames/hostname")
            hostname = hn_el.get("name", "") if hn_el is not None else ""
            os_el = h.find("os/osmatch")
            osn = os_el.get("name", "") if os_el is not None else ""
            ports: list[Port] = []
            for p in h.findall("ports/port"):
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc = p.find("service")
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                name = svc.get("name", "") if svc is not None else ""
                portid = int(p.get("portid", "0"))
                osi_layer, osi_label = _osi_of(portid, name)
                compliance = [Compliance(**c) for c in _COMPLIANCE.get(name.lower(), [])]
                suggestions = _SUGGEST.get(name.lower(), [])
                ports.append(Port(
                    port=portid, protocol=p.get("protocol", "tcp"), state="open",
                    service=name, product=product, version=version, cves=self.match_cves(product, version),
                    osi_layer=osi_layer, osi_label=osi_label, compliance=compliance, suggestions=suggestions,
                ))
            hosts.append(Host(ip=ip, hostname=hostname, os=osn, ports=ports))
        return hosts

    def _cmd(self, target: str, mode: str) -> list[str]:
        base = [self._nmap, "-sT", "-Pn", "-sV", "-oX", "-"]
        if mode == "complet":
            base += ["-p", "1-1024"]
        else:
            base += ["--top-ports", "100", "-T4"]
        base.append(target)
        return base

    def _run(self, target: str, mode: str) -> None:
        with self._lock:
            self._last = ScanResult(target=target, mode=mode, running=True, nmap_available=True)
        try:
            proc = subprocess.run(self._cmd(target, mode), capture_output=True, text=True,
                                  timeout=180, encoding="utf-8", errors="replace")
            hosts = self.parse(proc.stdout or "") if proc.stdout else []
            result = ScanResult(target=target, mode=mode, hosts=hosts, running=False, nmap_available=True)
        except subprocess.TimeoutExpired:
            result = ScanResult(target=target, mode=mode, running=False, error="timeout", nmap_available=True)
        except Exception as exc:
            result = ScanResult(target=target, mode=mode, running=False, error=str(exc), nmap_available=True)
        with self._lock:
            self._last = result
            self._running = False

    def run_async(self, target: str, mode: str = "discret") -> dict:
        if not self.nmap_available:
            return {"ok": False, "error": "nmap non installé"}
        if not self.valid_target(target):
            return {"ok": False, "error": "cible invalide"}
        with self._lock:
            if self._running:
                return {"ok": False, "error": "un scan est déjà en cours"}
            self._running = True
        threading.Thread(target=self._run, args=(target, mode), daemon=True).start()
        return {"ok": True, "running": True, "target": target}

    def get(self) -> ScanResult:
        with self._lock:
            return self._last or ScanResult(nmap_available=self.nmap_available)
