"""Module Windows Defender — état de protection + détections de menaces (factuel).

Interroge Microsoft Defender via PowerShell (Get-MpComputerStatus, Get-MpThreatDetection).
100 % lecture seule, données réelles de l'antivirus intégré. Hors Windows / Defender
absent → état dégradé, message clair, aucune donnée inventée. Exécution en tâche de
fond avec cache (les cmdlets Defender peuvent être lents).
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading

from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus


class DefenderThreat(BaseModel):
    time: str = ""
    threat: str = ""
    severity: str = ""
    action: str = ""
    resource: str = ""


class DefenderStatus(BaseModel):
    available: bool = False
    reason: str = ""
    antivirus_enabled: bool | None = None
    realtime_protection: bool | None = None
    antispyware_enabled: bool | None = None
    tamper_protection: bool | None = None
    signature_version: str = ""
    signature_age_days: float | None = None
    last_quick_scan: str = ""
    last_full_scan: str = ""
    threats: list[DefenderThreat] = []
    running: bool = False


def _ps(cmd: str, timeout: int = 25) -> tuple[bool, str]:
    """Exécute une commande PowerShell et renvoie (ok, stdout)."""
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace",
        )
        return (p.returncode == 0, p.stdout or "")
    except Exception:
        return (False, "")


class DefenderModule(Module):
    name = "defender"
    version = "0.1.0"
    description = "Windows Defender — protection + détections"
    produces = ["defender"]

    def __init__(self, bus: EventBus) -> None:
        super().__init__(bus)
        self._last: DefenderStatus | None = None
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        if not sys.platform.startswith("win"):
            self.set_status(ModuleStatus.NOT_INSTALLED, "Windows Defender disponible sur Windows uniquement")
            return
        self.set_status(ModuleStatus.ACTIVE)

    # -- collecte réelle -------------------------------------------------
    def _collect(self) -> DefenderStatus:
        st = DefenderStatus(running=False)
        ok, out = _ps("Get-MpComputerStatus | ConvertTo-Json -Depth 2")
        if not ok or not out.strip():
            st.available = False
            st.reason = "Defender injoignable (module ManagedDefender absent, ou droits insuffisants)"
            return st
        try:
            d = json.loads(out)
        except Exception:
            st.available = False
            st.reason = "réponse Defender illisible"
            return st
        st.available = True
        st.antivirus_enabled = d.get("AntivirusEnabled")
        st.realtime_protection = d.get("RealTimeProtectionEnabled")
        st.antispyware_enabled = d.get("AntispywareEnabled")
        st.tamper_protection = d.get("IsTamperProtected")
        st.signature_version = str(d.get("AntivirusSignatureVersion") or "")
        age = d.get("AntivirusSignatureAge")
        st.signature_age_days = float(age) if isinstance(age, (int, float)) else None
        st.last_quick_scan = str(d.get("QuickScanEndTime") or "")
        st.last_full_scan = str(d.get("FullScanEndTime") or "")
        st.threats = self._threats()
        return st

    def _threats(self) -> list[DefenderThreat]:
        ok, out = _ps("Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | "
                      "Select-Object -First 25 | ConvertTo-Json -Depth 2")
        if not ok or not out.strip():
            return []
        try:
            data = json.loads(out)
        except Exception:
            return []
        if isinstance(data, dict):
            data = [data]
        out_list: list[DefenderThreat] = []
        _ACTIONS = {0: "inconnu", 1: "nettoyé", 2: "quarantaine", 3: "supprimé", 6: "autorisé", 8: "bloqué", 9: "restauré"}
        _SEV = {0: "inconnu", 1: "faible", 2: "modéré", 4: "élevé", 5: "critique"}
        for t in data if isinstance(data, list) else []:
            if not isinstance(t, dict):
                continue
            res = t.get("Resources") or t.get("ProcessName") or ""
            if isinstance(res, list):
                res = res[0] if res else ""
            out_list.append(DefenderThreat(
                time=str(t.get("InitialDetectionTime") or ""),
                threat=str(t.get("ThreatName") or t.get("ThreatID") or "menace"),
                severity=_SEV.get(t.get("SeverityID"), str(t.get("SeverityID") or "")),
                action=_ACTIONS.get(t.get("CleaningActionID"), str(t.get("CleaningActionID") or "")),
                resource=str(res)[:200],
            ))
        return out_list

    def _run(self) -> None:
        result = self._collect()
        with self._lock:
            self._last = result
            self._running = False

    def run_async(self) -> dict:
        if not sys.platform.startswith("win"):
            return {"ok": False, "error": "Windows uniquement"}
        with self._lock:
            if self._running:
                return {"ok": True, "running": True}
            self._running = True
        threading.Thread(target=self._run, daemon=True).start()
        return {"ok": True, "running": True}

    def get(self) -> DefenderStatus:
        with self._lock:
            if self._last is not None:
                return self._last
        self.run_async()
        return DefenderStatus(running=True, reason="collecte en cours")
