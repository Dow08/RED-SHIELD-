"""Module WiFi Audit — alternative à aircrack, native Windows (netsh), sans installation.

aircrack (capture/crack de handshake) exige Linux + carte en mode monitor. En attendant,
ce module fait l'**audit WiFi** réel sous Windows : réseaux à portée, chiffrement, signal,
détection des réseaux ouverts/faibles. Recon/audit défensif, pas de cracking.
"""
from __future__ import annotations

import subprocess
import sys

from pydantic import BaseModel

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus


class WifiNetwork(BaseModel):
    ssid: str
    auth: str = ""
    encryption: str = ""
    channel: str = ""
    bssid: str = ""
    signal: int = 0
    risk: str = "safe"  # safe / watch / crit
    reason: str = ""


def _classify(auth: str) -> tuple[str, str]:
    a = auth.lower()
    if "wpa3" in a:
        return ("safe", "WPA3 (fort)")
    if "wpa2" in a:
        return ("safe", "WPA2")
    if "wep" in a:
        return ("crit", "WEP obsolète (cassable)")
    if "wpa" in a:
        return ("watch", "WPA1 (faible)")
    if a in ("", "ouvert", "open", "none"):
        return ("crit", "réseau ouvert (non chiffré)")
    return ("watch", auth)


class WifiModule(Module):
    name = "wifi"
    version = "0.1.0"
    description = "Audit WiFi (netsh) — alternative aircrack"
    produces = ["wifi"]

    def start(self) -> None:
        if not sys.platform.startswith("win"):
            self.set_status(ModuleStatus.NOT_INSTALLED, "Windows requis (netsh)")
            return
        self.set_status(ModuleStatus.ACTIVE)

    def _netsh(self, args: list[str]) -> str:
        proc = subprocess.run(["netsh", "wlan", *args], capture_output=True, text=True,
                              timeout=20, encoding="utf-8", errors="replace")
        return proc.stdout or ""

    def parse_networks(self, output: str) -> list[WifiNetwork]:
        nets: list[WifiNetwork] = []
        cur: dict | None = None

        def flush():
            if cur and cur.get("ssid"):
                risk, reason = _classify(cur.get("auth", ""))
                nets.append(WifiNetwork(
                    ssid=cur["ssid"], auth=cur.get("auth", ""), encryption=cur.get("enc", ""),
                    channel=cur.get("channel", ""), bssid=cur.get("bssid", ""),
                    signal=cur.get("signal", 0), risk=risk, reason=reason,
                ))

        for raw in output.splitlines():
            line = raw.strip()
            if not line or ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key.startswith("ssid") and "bssid" not in key:
                flush()
                cur = {"ssid": val or "(masqué)"}
            elif cur is None:
                continue
            elif key.startswith("bssid"):
                cur.setdefault("bssid", val)
            elif "authentif" in key or "authentic" in key:
                cur["auth"] = val
            elif "chiffr" in key or "encryption" in key or "cipher" in key:
                cur["enc"] = val
            elif key.startswith("signal"):
                try:
                    cur["signal"] = int(val.replace("%", "").strip())
                except ValueError:
                    pass
            elif key in ("canal", "channel", "chaîne") or key.startswith("canal") or key.startswith("channel"):
                cur["channel"] = val
        flush()
        # dédoublonne par SSID en gardant le meilleur signal
        best: dict[str, WifiNetwork] = {}
        for n in nets:
            if n.ssid not in best or n.signal > best[n.ssid].signal:
                best[n.ssid] = n
        return sorted(best.values(), key=lambda n: -n.signal)

    def get_networks(self) -> list[WifiNetwork]:
        if self.health() != ModuleStatus.ACTIVE:
            return []
        return self.parse_networks(self._netsh(["show", "networks", "mode=bssid"]))

    def result(self) -> dict:
        """Réseaux + message d'état (ex. service WiFi arrêté), pour l'UI."""
        if self.health() != ModuleStatus.ACTIVE:
            return {"networks": [], "message": "Audit WiFi disponible sous Windows uniquement."}
        raw = self._netsh(["show", "networks", "mode=bssid"])
        low = raw.lower()
        if "wlansvc" in low or "n’est pas en cours" in low or "is not running" in low:
            return {"networks": [], "message": "Service WiFi (wlansvc) non démarré — active le Wi-Fi ou démarre le service pour lancer l'audit."}
        if "powered down" in low or "interface" in low and "there are 0" in low:
            return {"networks": [], "message": "Aucun réseau détecté (adaptateur Wi-Fi éteint ?)."}
        nets = self.parse_networks(raw)
        return {"networks": [n.model_dump() for n in nets], "message": "" if nets else "Aucun réseau Wi-Fi à portée."}
