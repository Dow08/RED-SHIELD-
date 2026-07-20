"""Module Threat-Intel — réputation d'une IP (VirusTotal, AbuseIPDB).

Gated par le mode air-gapped ET la présence des clés (connecteurs). Sans clé / sous
air-gapped → « non connecté » (jamais de donnée inventée).
"""
from __future__ import annotations

import httpx

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus
from app.runtime import runtime


class IntelModule(Module):
    name = "intel"
    version = "0.1.0"
    description = "Réputation IP (VirusTotal, AbuseIPDB)"
    consumes = ["connectors"]

    def __init__(self, bus: EventBus, connectors) -> None:
        super().__init__(bus)
        self._conn = connectors

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    def lookup_ip(self, ip: str) -> dict:
        if runtime.airgapped:
            return {"available": False, "reason": "mode air-gapped actif — désactive-le pour interroger les sources", "sources": []}
        sources: list[dict] = []

        vt = self._conn.get("virustotal")
        if not vt:
            sources.append({"source": "VirusTotal", "error": "non connecté"})
        else:
            try:
                r = httpx.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                              headers={"x-apikey": vt}, timeout=15)
                if r.status_code == 200:
                    st = r.json()["data"]["attributes"]["last_analysis_stats"]
                    sources.append({"source": "VirusTotal", "malicious": st.get("malicious", 0),
                                    "suspicious": st.get("suspicious", 0), "harmless": st.get("harmless", 0)})
                else:
                    sources.append({"source": "VirusTotal", "error": f"HTTP {r.status_code}"})
            except Exception as exc:
                sources.append({"source": "VirusTotal", "error": str(exc)})

        abuse = self._conn.get("abuseipdb")
        if not abuse:
            sources.append({"source": "AbuseIPDB", "error": "non connecté"})
        else:
            try:
                r = httpx.get("https://api.abuseipdb.com/api/v2/check",
                              params={"ipAddress": ip, "maxAgeInDays": 90},
                              headers={"Key": abuse, "Accept": "application/json"}, timeout=15)
                if r.status_code == 200:
                    d = r.json()["data"]
                    sources.append({"source": "AbuseIPDB", "score": d.get("abuseConfidenceScore"),
                                    "reports": d.get("totalReports"), "country": d.get("countryCode")})
                else:
                    sources.append({"source": "AbuseIPDB", "error": f"HTTP {r.status_code}"})
            except Exception as exc:
                sources.append({"source": "AbuseIPDB", "error": str(exc)})

        return {"available": True, "ip": ip, "sources": sources}
