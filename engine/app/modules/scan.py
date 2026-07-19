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


class Port(BaseModel):
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    cves: list[Cve] = []


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
                ports.append(Port(
                    port=int(p.get("portid", "0")), protocol=p.get("protocol", "tcp"), state="open",
                    service=name, product=product, version=version, cves=self.match_cves(product, version),
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
