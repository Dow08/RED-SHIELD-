"""Module Découverte LAN — appareils du réseau local via la table ARP (passif).

Lit le cache ARP (arp -a) : IP + MAC des voisins déjà vus. Passif, instantané, réel.
Résolution fabricant via une table OUI intégrée (couverture partielle ; base OUI
complète = amélioration ultérieure).
"""
from __future__ import annotations

import re
import subprocess

from pydantic import BaseModel

from app.modules.base import Module, ModuleStatus

# Sous-ensemble d'OUI courants (préfixe MAC → fabricant). Couverture partielle assumée.
_OUI = {
    "fc:fb:fb": "Apple", "a4:83:e7": "Apple", "3c:22:fb": "Apple", "f0:18:98": "Apple",
    "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "00:1a:11": "Google", "f4:f5:e8": "Google", "d8:6c:63": "Google",
    "00:17:88": "Philips Hue", "ec:fa:bc": "Espressif", "a0:20:a6": "Espressif",
    "50:c7:bf": "TP-Link", "b0:be:76": "TP-Link", "00:1d:0f": "TP-Link",
    "00:24:d4": "Free (Freebox)", "68:a3:78": "Free (Freebox)", "8c:97:ea": "Free (Freebox)",
    "00:50:56": "VMware", "08:00:27": "VirtualBox", "00:15:5d": "Hyper-V",
}

_ROW = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})")


class LanDevice(BaseModel):
    ip: str
    mac: str
    vendor: str = ""


class LanModule(Module):
    name = "lan"
    version = "0.1.0"
    description = "Découverte LAN (table ARP)"
    produces = ["lan"]

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    def parse(self, output: str) -> list[LanDevice]:
        devices: list[LanDevice] = []
        seen: set[str] = set()
        for line in output.splitlines():
            m = _ROW.search(line)
            if not m:
                continue
            ip = m.group(1)
            mac = m.group(2).replace("-", ":").lower()
            first_octet = int(ip.split(".")[0])
            is_multicast = 224 <= first_octet <= 239 or mac.startswith(("01:00:5e", "33:33"))
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or ip.endswith(".255") or is_multicast or ip in seen:
                continue
            seen.add(ip)
            devices.append(LanDevice(ip=ip, mac=mac, vendor=_OUI.get(mac[:8], "")))
        return devices

    def devices(self) -> list[LanDevice]:
        try:
            p = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace")
        except Exception:
            return []
        return self.parse(p.stdout or "")
