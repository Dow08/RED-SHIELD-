"""Module Vulnérabilités des processus — croise les applications locales avec NVD (en ligne).

Pour chaque processus ayant des connexions réseau, extrait le **produit + version réels**
depuis les métadonnées de l'exécutable (VersionInfo Windows), puis interroge la base **NVD
en ligne** (module cve, gated air-gapped) → liens NVD. 100 % factuel : si aucune CVE n'est
renvoyée (ou air-gapped actif), c'est indiqué tel quel, jamais inventé.
"""
from __future__ import annotations

import sys
import threading

import psutil
from pydantic import BaseModel

from app.core import proc
from app.core.bus import EventBus
from app.modules import cve as cve_online
from app.modules.base import Module, ModuleStatus


class ProcCve(BaseModel):
    cve: str
    cvss: float
    severity: str
    summary: str
    url: str


class ProcVuln(BaseModel):
    process: str
    pid: int | None = None
    exe: str = ""
    product: str = ""
    version: str = ""
    cves: list[ProcCve] = []


class ProcVulnResult(BaseModel):
    apps: list[ProcVuln] = []
    scanned: int = 0
    running: bool = False
    available: bool = True
    note: str = ""


class ProcVulnModule(Module):
    name = "procvuln"
    version = "0.1.0"
    description = "CVE des applications locales (processus)"
    produces = ["procvuln"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._last: ProcVulnResult | None = None
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    # -- exécutables des process ayant des connexions -------------------
    @staticmethod
    def _connected_exes() -> dict[str, dict]:
        """Retourne {exe_path: {process, pid}} pour les process avec connexions distantes."""
        pids: dict[int, None] = {}
        for c in psutil.net_connections(kind="inet"):
            if c.raddr and c.pid:
                pids[c.pid] = None
        out: dict[str, dict] = {}
        for pid in pids:
            try:
                p = psutil.Process(pid)
                exe = p.exe()
                name = p.name()
            except Exception:
                continue
            if exe and exe not in out:
                out[exe] = {"process": name, "pid": pid}
        return out

    # -- version réelle via les métadonnées du fichier (Windows) --------
    @staticmethod
    def _versions(exes: list[str]) -> dict[str, dict]:
        if not exes or not sys.platform.startswith("win"):
            return {}
        arr = ",".join("'" + e.replace("'", "''") + "'" for e in exes[:40])
        cmd = ("@(" + arr + ") | ForEach-Object { try { $v=(Get-Item -LiteralPath $_).VersionInfo; "
               "[PSCustomObject]@{Path=$_;Product=$v.ProductName;Version=$v.ProductVersion} } catch {} } | ConvertTo-Json -Depth 2")
        ok, stdout = proc.powershell(cmd, timeout=30)
        try:
            data = json.loads(stdout or "null")
        except Exception:
            return {}
        if isinstance(data, dict):
            data = [data]
        res: dict[str, dict] = {}
        for d in data or []:
            if isinstance(d, dict) and d.get("Path"):
                res[d["Path"]] = {"product": (d.get("Product") or "").strip(), "version": (d.get("Version") or "").strip()}
        return res

    def _match(self, product: str, version: str) -> list[ProcCve]:
        """CVE via NVD en ligne (gated air-gapped). [] sous air-gapped ou sans produit."""
        if not (product or "").strip():
            return []
        res = cve_online.lookup(product, version)
        return [ProcCve(cve=c["cve"], cvss=c["cvss"], severity=c["severity"], summary=c["summary"], url=c["url"])
                for c in res.get("cves", [])]

    def _run(self) -> None:
        exes = self._connected_exes()
        versions = self._versions(list(exes.keys()))
        apps: list[ProcVuln] = []
        for exe, meta in exes.items():
            vi = versions.get(exe, {})
            product, version = vi.get("product", ""), vi.get("version", "")
            apps.append(ProcVuln(process=meta["process"], pid=meta["pid"], exe=exe,
                                 product=product, version=version, cves=self._match(product, version)))
        apps.sort(key=lambda a: (len(a.cves) == 0, a.process.lower()))
        note = "" if sys.platform.startswith("win") else "extraction de version disponible sur Windows uniquement"
        result = ProcVulnResult(apps=apps, scanned=len(apps), running=False, available=True, note=note)
        with self._lock:
            self._last = result
            self._running = False

    def run_async(self) -> dict:
        with self._lock:
            if self._running:
                return {"ok": True, "running": True}
            self._running = True
        threading.Thread(target=self._run, daemon=True).start()
        return {"ok": True, "running": True}

    def get(self) -> ProcVulnResult:
        with self._lock:
            if self._last is not None:
                return self._last
        self.run_async()
        return ProcVulnResult(running=True)
