"""Module Bilan de santé — état du poste (esprit CCleaner), 100 % factuel.

Lecture seule par défaut : espace disque, fichiers temporaires, programmes au démarrage,
redémarrage en attente. Le nettoyage des fichiers temporaires se fait en **dry-run**
(calcul de l'espace récupérable) puis **application sur confirmation** — jamais destructif
d'office, jamais de fichier hors des dossiers temp. Toutes les valeurs sont mesurées.
"""
from __future__ import annotations

import os
import sys
import time

import psutil
from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

if sys.platform.startswith("win"):
    import winreg
else:  # pragma: no cover
    winreg = None


class DiskInfo(BaseModel):
    device: str
    mountpoint: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent: float


class TempInfo(BaseModel):
    path: str
    size_mb: float
    files: int


class StartupItem(BaseModel):
    name: str
    command: str = ""
    source: str = ""


class HealthReport(BaseModel):
    available: bool = True
    platform_ok: bool = True
    disks: list[DiskInfo] = []
    temp_paths: list[TempInfo] = []
    temp_total_mb: float = 0.0
    startup: list[StartupItem] = []
    pending_reboot: bool = False
    reboot_reasons: list[str] = []
    recommendations: list[str] = []
    running: bool = False


class CleanResult(BaseModel):
    dry_run: bool = True
    reclaimable_mb: float = 0.0
    freed_mb: float = 0.0
    deleted_files: int = 0
    errors: int = 0


def _temp_dirs() -> list[str]:
    dirs = []
    for d in (os.environ.get("TEMP"), os.environ.get("TMP"), r"C:\Windows\Temp"):
        if d and os.path.isdir(d) and d not in dirs:
            dirs.append(os.path.normpath(d))
    return dirs


def _walk_size(path: str, cap: int = 60000) -> tuple[float, int]:
    total, files = 0, 0
    for root, _dirs, names in os.walk(path):
        for n in names:
            try:
                total += os.path.getsize(os.path.join(root, n))
                files += 1
            except OSError:
                pass
            if files >= cap:
                return (total / 1e6, files)
    return (total / 1e6, files)


class HealthModule(Module):
    name = "health"
    version = "0.1.0"
    description = "Bilan de santé du poste (disques, temp, démarrage)"
    produces = ["health"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._last: HealthReport | None = None
        self._running = False

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    # -- collecte (factuelle) -------------------------------------------
    def _disks(self) -> list[DiskInfo]:
        out: list[DiskInfo] = []
        for part in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(part.mountpoint)
            except Exception:
                continue
            out.append(DiskInfo(device=part.device, mountpoint=part.mountpoint,
                                total_gb=round(u.total / 1e9, 1), used_gb=round(u.used / 1e9, 1),
                                free_gb=round(u.free / 1e9, 1), percent=u.percent))
        return out

    def _startup(self) -> list[StartupItem]:
        items: list[StartupItem] = []
        if winreg is not None:
            for hive, path, src in (
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
            ):
                try:
                    with winreg.OpenKey(hive, path) as k:
                        i = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(k, i)
                            except OSError:
                                break
                            items.append(StartupItem(name=name, command=str(val)[:200], source=src))
                            i += 1
                except OSError:
                    pass
        startup_dir = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.isdir(startup_dir):
            for n in os.listdir(startup_dir):
                if not n.lower().startswith("desktop.ini"):
                    items.append(StartupItem(name=n, source="Dossier démarrage"))
        return items

    def _pending_reboot(self) -> tuple[bool, list[str]]:
        if winreg is None:
            return (False, [])
        reasons: list[str] = []
        checks = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", "Windows Update (composants)"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", "Windows Update"),
        ]
        for hive, path, why in checks:
            try:
                winreg.OpenKey(hive, path).Close()
                reasons.append(why)
            except OSError:
                pass
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager") as k:
                winreg.QueryValueEx(k, "PendingFileRenameOperations")
                reasons.append("Renommages de fichiers en attente")
        except OSError:
            pass
        return (len(reasons) > 0, reasons)

    def _report(self) -> HealthReport:
        r = HealthReport(platform_ok=sys.platform.startswith("win"))
        r.disks = self._disks()
        temps: list[TempInfo] = []
        total = 0.0
        for d in _temp_dirs():
            mb, files = _walk_size(d)
            temps.append(TempInfo(path=d, size_mb=round(mb, 1), files=files))
            total += mb
        r.temp_paths = temps
        r.temp_total_mb = round(total, 1)
        r.startup = self._startup()
        r.pending_reboot, r.reboot_reasons = self._pending_reboot()
        # Recommandations dérivées de l'état réel.
        recs: list[str] = []
        if total > 500:
            recs.append(f"~{round(total)} Mo de fichiers temporaires récupérables — lancer le nettoyage (dry-run d'abord).")
        for d in r.disks:
            if d.percent >= 90:
                recs.append(f"Disque {d.device} presque plein ({d.percent}%) — libérer de l'espace.")
        if len(r.startup) > 15:
            recs.append(f"{len(r.startup)} programmes au démarrage — en désactiver peut accélérer le boot.")
        if r.pending_reboot:
            recs.append("Redémarrage en attente — planifier un reboot pour finaliser des mises à jour.")
        if not recs:
            recs.append("Poste en bonne santé : rien de prioritaire détecté.")
        r.recommendations = recs
        return r

    def run_async(self) -> dict:
        import threading
        if self._running:
            return {"ok": True, "running": True}
        self._running = True
        def _job():
            try:
                self._last = self._report()
            finally:
                self._running = False
        threading.Thread(target=_job, daemon=True).start()
        return {"ok": True, "running": True}

    def get(self) -> HealthReport:
        if self._last is not None:
            return self._last
        self.run_async()
        return HealthReport(running=True)

    # -- nettoyage temp : dry-run puis application sur confirmation ------
    def clean_temp(self, dry_run: bool = True) -> CleanResult:
        reclaimable = 0.0
        freed = 0.0
        deleted = 0
        errors = 0
        now = time.time()
        for d in _temp_dirs():
            for root, _dirs, names in os.walk(d):
                for n in names:
                    fp = os.path.join(root, n)
                    try:
                        size = os.path.getsize(fp)
                    except OSError:
                        continue
                    # sécurité : ne toucher qu'aux fichiers modifiés il y a > 1h (évite les fichiers en cours d'usage)
                    try:
                        if now - os.path.getmtime(fp) < 3600:
                            continue
                    except OSError:
                        continue
                    reclaimable += size
                    if not dry_run:
                        try:
                            os.remove(fp)
                            freed += size
                            deleted += 1
                        except OSError:
                            errors += 1
        if not dry_run:
            self.bus.publish("log", {"level": "warn", "module": self.name,
                                     "message": f"nettoyage temp : {deleted} fichier(s), {round(freed/1e6)} Mo libérés"})
        return CleanResult(dry_run=dry_run, reclaimable_mb=round(reclaimable / 1e6, 1),
                           freed_mb=round(freed / 1e6, 1), deleted_files=deleted, errors=errors)
