"""Module OSINT passif — énumération de sous-domaines via crt.sh (sans clé).

Recon passif (aucun paquet vers la cible) : interroge la transparence des certificats.
Gated par le mode air-gapped (crt.sh = source externe). Inspiré de sk-enumpassive.
"""
from __future__ import annotations

import re

from app.core import http
from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus
from app.runtime import runtime

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


class OsintModule(Module):
    name = "osint"
    version = "0.1.0"
    description = "OSINT passif (crt.sh)"
    produces = ["osint"]

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    def subdomains(self, domain: str) -> dict:
        if runtime.airgapped:
            return {"available": False, "reason": "mode air-gapped actif — désactive-le pour l'OSINT", "subdomains": []}
        if not _DOMAIN_RE.match(domain):
            return {"available": True, "error": "domaine invalide", "subdomains": []}
        r = http.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if r.error:
            return {"available": True, "error": r.error, "subdomains": []}
        if r.status_code != 200:
            return {"available": True, "error": f"crt.sh HTTP {r.status_code}", "subdomains": []}
        try:
            data = r.json() or []
            subs = set()
            for entry in data:
                for name in str(entry.get("name_value", "")).split("\n"):
                    name = name.strip().lower()
                    if name and "*" not in name and domain in name:
                        subs.add(name)
            return {"available": True, "domain": domain, "subdomains": sorted(subs)[:300]}
        except Exception as exc:
            return {"available": True, "error": str(exc), "subdomains": []}
