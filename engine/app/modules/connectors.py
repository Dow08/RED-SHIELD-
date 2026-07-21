"""Module Connecteurs — stockage chiffré des clés API (keyring / Credential Manager).

Les clés ne sont jamais en clair : elles sont écrites dans le trousseau de l'OS.
L'utilisateur les ajoute/modifie/supprime lui-même. RED ne les affiche jamais.
"""
from __future__ import annotations

import keyring

from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus

SERVICE = "RED-connectors"
# Connecteurs à clé API affichés dans l'onglet Connecteurs.
KNOWN = ["virustotal", "abuseipdb", "greynoise", "shodan", "llm"]
# Ensemble complet des noms acceptés (inclut les connecteurs à config JSON : imap, siem).
# Toute écriture/lecture hors de cette liste blanche est refusée (pas de pollution du
# trousseau via un nom arbitraire passé en paramètre d'URL).
ALLOWED = set(KNOWN) | {"imap", "siem"}


class ConnectorsModule(Module):
    name = "connectors"
    version = "0.1.0"
    description = "Connecteurs (clés API chiffrées)"
    produces = ["connectors"]

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    def get(self, name: str) -> str | None:
        if name not in ALLOWED:
            return None
        try:
            return keyring.get_password(SERVICE, name)
        except Exception:
            return None

    def set(self, name: str, value: str) -> None:
        if name not in ALLOWED:
            raise ValueError("connecteur inconnu")
        keyring.set_password(SERVICE, name, value)
        # On ne journalise JAMAIS la valeur (secret) — seulement le nom du connecteur.
        self.bus.publish("log", {"level": "info", "module": self.name, "message": f"connecteur '{name}' configuré"})

    def delete(self, name: str) -> None:
        if name not in ALLOWED:
            raise ValueError("connecteur inconnu")
        try:
            keyring.delete_password(SERVICE, name)
            self.bus.publish("log", {"level": "info", "module": self.name, "message": f"connecteur '{name}' supprimé"})
        except Exception:
            pass

    def status(self) -> list[dict]:
        return [{"name": n, "connected": bool(self.get(n))} for n in KNOWN]
