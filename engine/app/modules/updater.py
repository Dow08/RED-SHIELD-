"""Module Mise à jour des applications — via winget (gestionnaire de paquets officiel Microsoft).

Liste les applications ayant une mise à jour disponible depuis des **sources connues/officielles**
(winget), et permet de les installer (dry-run → confirmation, ou en un clic). 100 % factuel :
les données viennent directement de winget, aucun tiers opaque, rien d'inventé. L'installation
est une action explicite de l'utilisateur (jamais automatique sans confirmation).
"""
from __future__ import annotations

import re
import shutil
import threading

from pydantic import BaseModel

from app.core import proc
from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-+_]{0,100}$")


def parse_upgrade_table(output: str) -> list[dict]:
    """Parse la sortie tabulaire de `winget upgrade` (colonnes à largeur fixe).

    Robuste : repère les positions des colonnes depuis l'en-tête, découpe chaque ligne
    par ces positions. Ignore le séparateur, les lignes de progression et le pied de page.
    """
    lines = output.splitlines()
    header_idx = -1
    for i, line in enumerate(lines):
        if "Id" in line and "Version" in line and ("Available" in line or "Disponible" in line):
            header_idx = i
            break
    if header_idx < 0:
        return []
    header = lines[header_idx]
    avail_key = "Available" if "Available" in header else "Disponible"
    src_key = "Source"
    try:
        c_name = header.index("Name") if "Name" in header else (header.index("Nom") if "Nom" in header else 0)
        c_id = header.index("Id")
        c_ver = header.index("Version")
        c_av = header.index(avail_key)
        c_src = header.index(src_key) if src_key in header else len(header)
    except ValueError:
        return []
    out: list[dict] = []
    for line in lines[header_idx + 1:]:
        s = line.strip()
        if not s or set(s) <= {"-", " "}:            # séparateur
            continue
        if re.match(r"^\d+\s+(upgrade|mise)", s, re.IGNORECASE):  # pied de page « N upgrades available »
            break
        if len(line) < c_av:                          # ligne de progression/partielle
            continue
        name = line[c_name:c_id].strip()
        app_id = line[c_id:c_ver].strip()
        version = line[c_ver:c_av].strip()
        available = line[c_av:c_src].strip()
        source = line[c_src:].strip()
        if app_id and version and available and _ID_RE.match(app_id):
            out.append({"name": name, "id": app_id, "current": version, "available": available, "source": source})
    return out


class AppUpdate(BaseModel):
    name: str
    id: str
    current: str
    available: str
    source: str = ""


class UpdaterResult(BaseModel):
    available_tool: bool = False
    reason: str = ""
    updates: list[AppUpdate] = []
    running: bool = False


class UpdaterModule(Module):
    name = "updater"
    version = "0.1.0"
    description = "Mises à jour des applications (winget)"
    produces = ["updater"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._winget: str | None = None
        self._last: UpdaterResult | None = None
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        self._winget = shutil.which("winget")
        self.set_status(ModuleStatus.ACTIVE if self._winget else ModuleStatus.NOT_INSTALLED,
                        "" if self._winget else "winget introuvable (Windows 10/11)")

    # -- liste des mises à jour ------------------------------------------
    def _collect(self) -> UpdaterResult:
        if not self._winget:
            return UpdaterResult(available_tool=False, reason="winget introuvable")
        ok, stdout, err = proc.run(
            [self._winget, "upgrade", "--accept-source-agreements", "--include-unknown"], timeout=90)
        if not ok and not stdout:
            return UpdaterResult(available_tool=True, reason=err or "échec winget")
        updates = [AppUpdate(**u) for u in parse_upgrade_table(stdout or "")]
        return UpdaterResult(available_tool=True, updates=updates)

    def _run(self) -> None:
        result = self._collect()
        with self._lock:
            self._last = result
            self._running = False

    def run_async(self) -> dict:
        if not self._winget:
            return {"ok": False, "error": "winget introuvable"}
        with self._lock:
            if self._running:
                return {"ok": True, "running": True}
            self._running = True
        threading.Thread(target=self._run, daemon=True).start()
        return {"ok": True, "running": True}

    def get(self) -> UpdaterResult:
        with self._lock:
            if self._last is not None:
                return self._last
        self.run_async()
        return UpdaterResult(available_tool=bool(self._winget), running=True)

    # -- installation d'une mise à jour (action explicite) ---------------
    def upgrade(self, app_id: str, dry_run: bool = True) -> dict:
        if not _ID_RE.match(app_id or ""):
            return {"ok": False, "error": "identifiant d'application invalide"}
        cmd = [self._winget or "winget", "upgrade", "--id", app_id, "--exact", "--silent",
               "--accept-package-agreements", "--accept-source-agreements"]
        if dry_run:
            return {"ok": True, "dry_run": True, "command": " ".join(cmd)}
        if not self._winget:
            return {"ok": False, "error": "winget introuvable"}
        try:
            ok, stdout, stderr = proc.run(cmd, timeout=900)
            if stderr == "timeout":
                return {"ok": False, "error": "délai dépassé (installation trop longue)"}
            self.bus.publish("log", {"level": "warn" if ok else "error", "module": self.name,
                                     "message": f"maj {app_id}: {'ok' if ok else 'echec'}"})
            return {"ok": ok, "output": (stdout or stderr).strip()[-600:], "returncode": 0 if ok else 1}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
