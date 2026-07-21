"""Module HIDS-lite — surveillance des événements Windows (mini-SOC local, sans SIEM).

Lit le journal d'événements (Get-WinEvent) et remonte les événements sensibles :
services installés, échecs de connexion, création de comptes, détections Defender,
events Sysmon si présent. Lecture seule ; certains events (Security) exigent l'admin.
Exécution en tâche de fond avec cache.
"""
from __future__ import annotations

import json
import sys
import threading

from pydantic import BaseModel

from app.core import proc
from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

# (log, [event ids], sévérité, libellé)
_RULES: list[tuple[str, list[int], str, str]] = [
    ("System", [7045], "watch", "Nouveau service installé"),
    ("System", [7040], "info", "Démarrage de service modifié"),
    ("Security", [4625], "watch", "Échec de connexion"),
    ("Security", [4720], "crit", "Compte utilisateur créé"),
    ("Security", [4672], "info", "Privilèges spéciaux à la connexion"),
    ("Security", [1102], "crit", "Journal de sécurité effacé"),
    ("Microsoft-Windows-Windows Defender/Operational", [1116, 1117], "crit", "Menace détectée / action Defender"),
    ("Microsoft-Windows-Sysmon/Operational", [1], "info", "Création de process (Sysmon)"),
    ("Microsoft-Windows-Sysmon/Operational", [3], "watch", "Connexion réseau (Sysmon)"),
]


class HidsEvent(BaseModel):
    ts: str
    log: str
    event_id: int
    severity: str
    label: str
    message: str = ""


class HidsResult(BaseModel):
    events: list[HidsEvent] = []
    running: bool = False
    available: bool = True
    note: str = ""


class HidsModule(Module):
    name = "hids"
    version = "0.1.0"
    description = "HIDS-lite (journal d'événements Windows)"
    produces = ["hids"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._last: HidsResult | None = None
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        if sys.platform.startswith("win"):
            self.set_status(ModuleStatus.ACTIVE)
        else:
            self.set_status(ModuleStatus.NOT_INSTALLED, "Windows requis (Get-WinEvent)")

    def _query(self, log: str, ids: list[int], count: int = 8) -> list[dict]:
        ids_csv = ",".join(str(i) for i in ids)
        ps = (
            "$ErrorActionPreference='SilentlyContinue';"
            f"Get-WinEvent -FilterHashtable @{{LogName='{log}';Id={ids_csv}}} -MaxEvents {count} |"
            " Select-Object @{n='ts';e={$_.TimeCreated.ToString('o')}},@{n='id';e={$_.Id}},"
            "@{n='msg';e={($_.Message -replace '\\s+',' ')}} | ConvertTo-Json -Compress"
        )
        ok, stdout = proc.powershell(ps, timeout=20)
        out = (stdout or "").strip()
        if not out:
            return []
        try:
            data = json.loads(out)
        except Exception:
            return []
        return data if isinstance(data, list) else [data]

    def _run(self) -> None:
        with self._lock:
            self._last = HidsResult(running=True)
        events: list[HidsEvent] = []
        for log, ids, sev, label in _RULES:
            for ev in self._query(log, ids):
                msg = str(ev.get("msg", ""))[:180]
                events.append(HidsEvent(ts=str(ev.get("ts", "")), log=log, event_id=int(ev.get("id", 0)),
                                        severity=sev, label=label, message=msg))
        events.sort(key=lambda e: e.ts, reverse=True)
        note = "" if any(e.log == "Security" for e in events) else "Astuce : lancer RED en administrateur pour lire le journal Sécurité (échecs de connexion)."
        with self._lock:
            self._last = HidsResult(events=events, running=False, available=True, note=note)
            self._running = False

    def run_async(self) -> dict:
        if self.health() != ModuleStatus.ACTIVE:
            return {"ok": False, "error": "Windows requis"}
        with self._lock:
            if self._running:
                return {"ok": False, "error": "analyse déjà en cours"}
            self._running = True
        threading.Thread(target=self._run, daemon=True).start()
        return {"ok": True, "running": True}

    def get(self) -> HidsResult:
        with self._lock:
            return self._last or HidsResult(available=self.health() == ModuleStatus.ACTIVE)
