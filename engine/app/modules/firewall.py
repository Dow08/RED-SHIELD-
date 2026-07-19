"""Module Firewall — couper/autoriser une connexion via le pare-feu Windows.

Action privilégiée : dry-run par défaut (montre la commande), application avec
confirmation côté UI, annulation possible, et journalisation (audit). Nécessite
les droits administrateur pour appliquer réellement.
"""
from __future__ import annotations

import ipaddress
import subprocess
import sys

from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus


class FwRequest(BaseModel):
    ip: str
    dry_run: bool = True


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class FirewallModule(Module):
    name = "firewall"
    version = "0.1.0"
    description = "Couper/autoriser (pare-feu Windows)"
    produces = ["firewall"]

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE if sys.platform.startswith("win") else ModuleStatus.NOT_INSTALLED)

    def _rule(self, ip: str) -> str:
        return f"RED-block-{ip}"

    def _run(self, cmd: list[str], ip: str, action: str) -> dict:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace")
            combined = f"{p.stdout}{p.stderr}".lower()
            ok = p.returncode == 0
            self.bus.publish("log", {"level": "warn" if ok else "error", "module": self.name,
                                     "message": f"{action} {ip}: {'appliqué' if ok else 'échec'}"})
            if not ok and ("admin" in combined or "requis" in combined or "elevation" in combined or "élev" in combined):
                return {"ok": False, "error": "nécessite les droits administrateur (lancer RED en admin)"}
            return {"ok": ok, "output": (p.stdout or p.stderr).strip()[:400]}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def block(self, ip: str, dry_run: bool = True) -> dict:
        if not _valid_ip(ip):
            return {"ok": False, "error": "IP invalide"}
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={self._rule(ip)}",
               "dir=out", "action=block", f"remoteip={ip}"]
        if dry_run:
            return {"ok": True, "dry_run": True, "command": " ".join(cmd)}
        if self.health() != ModuleStatus.ACTIVE:
            return {"ok": False, "error": "pare-feu Windows uniquement"}
        return self._run(cmd, ip, "block")

    def unblock(self, ip: str) -> dict:
        if not _valid_ip(ip):
            return {"ok": False, "error": "IP invalide"}
        if self.health() != ModuleStatus.ACTIVE:
            return {"ok": False, "error": "pare-feu Windows uniquement"}
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={self._rule(ip)}"]
        return self._run(cmd, ip, "unblock")

    def list_rules(self) -> list[str]:
        if self.health() != ModuleStatus.ACTIVE:
            return []
        try:
            p = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                               capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace")
        except Exception:
            return []
        out: list[str] = []
        for line in p.stdout.splitlines():
            low = line.strip().lower()
            if low.startswith("rule name") or low.startswith("nom de la règle"):
                name = line.split(":", 1)[1].strip() if ":" in line else ""
                if name.startswith("RED-block-"):
                    out.append(name.replace("RED-block-", ""))
        return out
