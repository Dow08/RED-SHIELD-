"""Module Bilan de santé — état du poste (esprit CCleaner), 100 % factuel.

Lecture seule par défaut : espace disque, catégories nettoyables (temp, corbeille,
caches navigateurs, cookies, miniatures, cache Windows Update), programmes au démarrage,
redémarrage en attente, Windows.old, plus gros fichiers, mémoire vive.

Nettoyage : **dry-run** (espace récupérable) puis **application sur confirmation** — jamais
destructif d'office, jamais hors des dossiers ciblés, protège les fichiers en cours d'usage.
Actions système (désactiver un programme au démarrage, point de restauration) : réversibles
/ avec sauvegarde. Toutes les valeurs sont mesurées, rien n'est inventé.
"""
from __future__ import annotations

import ctypes
import glob
import heapq
import json
import os
import sys
import time

import psutil
from pydantic import BaseModel

from app.core import proc
from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

if sys.platform.startswith("win"):
    import winreg
else:  # pragma: no cover
    winreg = None

_LOCAL = os.environ.get("LOCALAPPDATA", "")
_PROFILE = os.environ.get("USERPROFILE", "")
_STARTUP_BACKUP = r"Software\RED-SHIELD\StartupDisabled"  # HKCU : sauvegarde pour réactivation


class DiskInfo(BaseModel):
    device: str
    mountpoint: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent: float


class Cleanable(BaseModel):
    id: str
    label: str
    size_mb: float = 0.0
    files: int = 0
    admin: bool = False
    warn: str = ""


class StartupItem(BaseModel):
    name: str
    command: str = ""
    source: str = ""
    enabled: bool = True


class BigFile(BaseModel):
    path: str
    size_mb: float


class ProcMem(BaseModel):
    process: str
    mb: float


class HealthReport(BaseModel):
    available: bool = True
    platform_ok: bool = True
    disks: list[DiskInfo] = []
    cleanables: list[Cleanable] = []
    cleanable_total_mb: float = 0.0
    startup: list[StartupItem] = []
    pending_reboot: bool = False
    reboot_reasons: list[str] = []
    windows_old: bool = False
    largest_files: list[BigFile] = []
    ram_percent: float = 0.0
    ram_total_gb: float = 0.0
    ram_used_gb: float = 0.0
    top_memory: list[ProcMem] = []
    recommendations: list[str] = []
    running: bool = False


class CleanResult(BaseModel):
    category: str = ""
    dry_run: bool = True
    reclaimable_mb: float = 0.0
    freed_mb: float = 0.0
    deleted_files: int = 0
    errors: int = 0
    error: str = ""


# --- catégories nettoyables (dossiers résolus dynamiquement) ------------
def _temp_dirs() -> list[str]:
    out = []
    for d in (os.environ.get("TEMP"), os.environ.get("TMP"), r"C:\Windows\Temp"):
        if d and os.path.isdir(d) and os.path.normpath(d) not in out:
            out.append(os.path.normpath(d))
    return out


def _browser_dirs(vendor: str, sub: str) -> list[str]:
    """Sous-dossiers `sub` (ex. 'Cache') de tous les profils d'un navigateur Chromium."""
    base = os.path.join(_LOCAL, vendor, "User Data")
    dirs: list[str] = []
    if os.path.isdir(base):
        for prof in os.listdir(base):
            p = os.path.join(base, prof, *sub.split("/"))
            if os.path.isdir(p):
                dirs.append(p)
    return dirs


def _firefox_cache() -> list[str]:
    return [d for d in glob.glob(os.path.join(_LOCAL, r"Mozilla\Firefox\Profiles\*\cache2")) if os.path.isdir(d)]


def _category_dirs(cat: str) -> list[str]:
    if cat == "temp":
        return _temp_dirs()
    if cat == "chrome_cache":
        return _browser_dirs(r"Google\Chrome", "Cache") + _browser_dirs(r"Google\Chrome", "Code Cache")
    if cat == "edge_cache":
        return _browser_dirs(r"Microsoft\Edge", "Cache") + _browser_dirs(r"Microsoft\Edge", "Code Cache")
    if cat == "firefox_cache":
        return _firefox_cache()
    if cat == "thumbnails":
        return [os.path.join(_LOCAL, r"Microsoft\Windows\Explorer")]
    if cat == "winupdate":
        return [r"C:\Windows\SoftwareDistribution\Download"]
    return []


_CATS = [
    ("temp", "Fichiers temporaires", False, ""),
    ("recycle", "Corbeille", False, ""),
    ("chrome_cache", "Cache Chrome", False, ""),
    ("edge_cache", "Cache Edge", False, ""),
    ("firefox_cache", "Cache Firefox", False, ""),
    ("thumbnails", "Miniatures (explorateur)", False, "verrouillé si l'explorateur est ouvert"),
    ("winupdate", "Cache Windows Update", True, "nécessite les droits admin"),
]


def _dir_size(path: str, cap: int = 40000) -> tuple[float, int]:
    """Taille approximative d'un dossier via os.scandir (stat en cache = rapide), borné."""
    total, files = 0, 0
    stack = [path]
    while stack and files < cap:
        try:
            it = os.scandir(stack.pop())
        except OSError:
            continue
        with it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        total += e.stat(follow_symlinks=False).st_size
                        files += 1
                except OSError:
                    pass
                if files >= cap:
                    break
    return (total / 1e6, files)


# --- corbeille (API shell Windows) --------------------------------------
class _SHQRBI(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_ulong), ("i64Size", ctypes.c_int64), ("i64NumItems", ctypes.c_int64)]


def _recycle_size() -> tuple[float, int]:
    if not sys.platform.startswith("win"):
        return (0.0, 0)
    info = _SHQRBI()
    info.cbSize = ctypes.sizeof(_SHQRBI)
    try:
        res = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
        if res != 0:
            return (0.0, 0)
        return (info.i64Size / 1e6, int(info.i64NumItems))
    except Exception:
        return (0.0, 0)


def _recycle_empty() -> bool:
    try:
        # 0x7 = SHERB_NOCONFIRMATION | NOPROGRESSUI | NOSOUND
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x7)
        return True
    except Exception:
        return False


class HealthModule(Module):
    name = "health"
    version = "0.2.0"
    description = "Bilan de santé du poste (disques, nettoyage, démarrage, mémoire)"
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

    def _cleanables(self) -> tuple[list[Cleanable], float]:
        out: list[Cleanable] = []
        total = 0.0
        for cid, label, admin, warn in _CATS:
            if cid == "recycle":
                mb, files = _recycle_size()
            else:
                mb, files = 0.0, 0
                for d in _category_dirs(cid):
                    s, f = _dir_size(d)
                    mb += s
                    files += f
            total += mb
            out.append(Cleanable(id=cid, label=label, size_mb=round(mb, 1), files=files, admin=admin, warn=warn))
        return (out, round(total, 1))

    def _disabled_names(self) -> set[str]:
        if winreg is None:
            return set()
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _STARTUP_BACKUP) as k:
                names, i = set(), 0
                while True:
                    try:
                        n, _v, _t = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    names.add(n)
                    i += 1
                return names
        except OSError:
            return set()

    def _startup(self) -> list[StartupItem]:
        items: list[StartupItem] = []
        disabled = self._disabled_names()
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
                            items.append(StartupItem(name=name, command=str(val)[:200], source=src, enabled=True))
                            i += 1
                except OSError:
                    pass
        for n in disabled:  # entrées désactivées par RED (sauvegardées), affichées comme telles
            items.append(StartupItem(name=n, source="HKCU\\Run (désactivé)", enabled=False))
        startup_dir = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.isdir(startup_dir):
            for n in os.listdir(startup_dir):
                if not n.lower().startswith("desktop.ini"):
                    items.append(StartupItem(name=n, source="Dossier démarrage", enabled=True))
        return items

    def _pending_reboot(self) -> tuple[bool, list[str]]:
        if winreg is None:
            return (False, [])
        reasons: list[str] = []
        for hive, path, why in [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", "Windows Update (composants)"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", "Windows Update"),
        ]:
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

    def _largest_files(self, top: int = 10, cap: int = 60000) -> list[BigFile]:
        """Plus gros fichiers dans les dossiers utilisateur usuels (rapide et pertinent :
        on évite node_modules/AppData qui feraient exploser le temps de scan)."""
        if not _PROFILE or not os.path.isdir(_PROFILE):
            return []
        roots = [os.path.join(_PROFILE, d) for d in
                 ("Downloads", "Documents", "Desktop", "Videos", "Pictures", "Music")]
        heap: list[tuple[int, str]] = []
        seen = 0
        stack = [b for b in roots if os.path.isdir(b)]
        while stack and seen < cap:
            try:
                it = os.scandir(stack.pop())
            except OSError:
                continue
            with it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if e.name.lower() not in ("node_modules", ".git", "__pycache__"):
                                stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            sz = e.stat(follow_symlinks=False).st_size
                            seen += 1
                            if len(heap) < top:
                                heapq.heappush(heap, (sz, e.path))
                            elif sz > heap[0][0]:
                                heapq.heapreplace(heap, (sz, e.path))
                    except OSError:
                        pass
                    if seen >= cap:
                        break
        return [BigFile(path=p, size_mb=round(s / 1e6, 1)) for s, p in sorted(heap, reverse=True)]

    def _memory(self) -> tuple[float, float, float, list[ProcMem]]:
        vm = psutil.virtual_memory()
        procs: dict[str, float] = {}
        for p in psutil.process_iter(["name", "memory_info"]):
            try:
                nm = p.info["name"] or "?"
                rss = p.info["memory_info"].rss if p.info["memory_info"] else 0
                procs[nm] = procs.get(nm, 0.0) + rss
            except Exception:
                pass
        top = sorted(procs.items(), key=lambda kv: kv[1], reverse=True)[:6]
        return (vm.percent, round(vm.total / 1e9, 1), round(vm.used / 1e9, 1),
                [ProcMem(process=k, mb=round(v / 1e6, 1)) for k, v in top])

    def _report(self) -> HealthReport:
        r = HealthReport(platform_ok=sys.platform.startswith("win"))
        r.disks = self._disks()
        r.cleanables, r.cleanable_total_mb = self._cleanables()
        r.startup = self._startup()
        r.pending_reboot, r.reboot_reasons = self._pending_reboot()
        r.windows_old = os.path.isdir(r"C:\Windows.old")
        r.largest_files = self._largest_files()
        r.ram_percent, r.ram_total_gb, r.ram_used_gb, r.top_memory = self._memory()
        recs: list[str] = []
        if r.cleanable_total_mb > 500:
            recs.append(f"~{round(r.cleanable_total_mb)} Mo nettoyables (temp, caches…) — lance un nettoyage (dry-run d'abord).")
        for d in r.disks:
            if d.percent >= 90:
                recs.append(f"Disque {d.device} presque plein ({d.percent}%) — libérer de l'espace.")
        if r.windows_old:
            recs.append("Dossier Windows.old présent (plusieurs Go) — supprimable via le Nettoyage de disque Windows.")
        if r.ram_percent >= 85:
            recs.append(f"Mémoire vive à {r.ram_percent}% — fermer des applications gourmandes.")
        if r.pending_reboot:
            recs.append("Redémarrage en attente — planifie un reboot pour finaliser des mises à jour.")
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

    # -- nettoyage d'une catégorie : dry-run puis application ------------
    def clean(self, category: str, dry_run: bool = True) -> CleanResult:
        res = CleanResult(category=category, dry_run=dry_run)
        if category == "recycle":
            mb, _files = _recycle_size()
            res.reclaimable_mb = round(mb, 1)
            if not dry_run:
                if _recycle_empty():
                    res.freed_mb = res.reclaimable_mb
                    self.bus.publish("log", {"level": "warn", "module": self.name, "message": f"corbeille vidée ({round(mb)} Mo)"})
                else:
                    res.error = "échec du vidage de la corbeille"
            return res
        dirs = _category_dirs(category)
        if not dirs:
            res.error = "catégorie inconnue"
            return res
        now = time.time()
        reclaimable = freed = 0.0
        for d in dirs:
            for root, subdirs, names in os.walk(d):
                # Défense en profondeur : ne JAMAIS descendre dans un lien/jonction
                # (un cache piégé pourrait pointer hors du dossier ciblé).
                subdirs[:] = [sd for sd in subdirs if not os.path.islink(os.path.join(root, sd))]
                for n in names:
                    fp = os.path.join(root, n)
                    try:
                        if os.path.islink(fp):     # on ne suit pas les liens symboliques
                            continue
                        size = os.path.getsize(fp)
                        if now - os.path.getmtime(fp) < 3600:   # protège les fichiers récents / en usage
                            continue
                    except OSError:
                        continue
                    reclaimable += size
                    if not dry_run:
                        try:
                            os.remove(fp)
                            freed += size
                            res.deleted_files += 1
                        except OSError:
                            res.errors += 1
        res.reclaimable_mb = round(reclaimable / 1e6, 1)
        res.freed_mb = round(freed / 1e6, 1)
        if not dry_run:
            self.bus.publish("log", {"level": "warn", "module": self.name,
                                     "message": f"nettoyage {category}: {res.deleted_files} fichiers, {res.freed_mb} Mo"})
        return res

    # -- désactiver / réactiver un programme au démarrage (réversible) ---
    def set_startup(self, name: str, enabled: bool) -> dict:
        if winreg is None:
            return {"ok": False, "error": "Windows uniquement"}
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            if not enabled:
                # lit la valeur, la sauvegarde dans la clé RED, puis la retire du Run
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_READ) as k:
                    val, typ = winreg.QueryValueEx(k, name)
                winreg.CreateKey(winreg.HKEY_CURRENT_USER, _STARTUP_BACKUP)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _STARTUP_BACKUP, 0, winreg.KEY_SET_VALUE) as bk:
                    winreg.SetValueEx(bk, name, 0, typ, val)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, name)
                action = "désactivé"
            else:
                # restaure depuis la sauvegarde RED
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _STARTUP_BACKUP, 0, winreg.KEY_READ) as bk:
                    val, typ = winreg.QueryValueEx(bk, name)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.SetValueEx(k, name, 0, typ, val)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _STARTUP_BACKUP, 0, winreg.KEY_SET_VALUE) as bk:
                    winreg.DeleteValue(bk, name)
                action = "réactivé"
            self.bus.publish("log", {"level": "warn", "module": self.name, "message": f"démarrage {action}: {name}"})
            return {"ok": True, "name": name, "enabled": enabled}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    # -- point de restauration système (filet de sécurité) --------------
    def create_restore_point(self, description: str = "RED SHIELD - avant maintenance") -> dict:
        if not sys.platform.startswith("win"):
            return {"ok": False, "error": "Windows uniquement"}
        desc = "".join(c for c in description if c.isalnum() or c in " -_")[:60]
        ok, out, err = proc.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f'Checkpoint-Computer -Description "{desc}" -RestorePointType MODIFY_SETTINGS'],
            timeout=120)
        if ok:
            self.bus.publish("log", {"level": "warn", "module": self.name, "message": "point de restauration créé"})
            return {"ok": True}
        return {"ok": False, "error": (err or out or "échec").strip()[:300] +
                " (nécessite admin + Protection système activée)"}
