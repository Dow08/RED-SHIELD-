"""Module SIEM/EDR — connecteur de récupération de logs/alertes depuis un SIEM externe.

Fonctionnel et factuel : lit la config du connecteur « siem » (type/url/token, chiffrée
en keyring), teste réellement la connexion et récupère les alertes via l'API REST du
SIEM. Gated par le mode air-gapped ET la présence d'une config → sinon « non connecté »
(jamais de donnée inventée). L'EDR local de la machine est fourni par le module Defender.

Types supportés : « wazuh » (API REST), « elastic » (_search), « generic » (endpoint JSON
renvoyant une liste d'alertes). Sans instance configurée, l'onglet reste inerte et honnête.
"""
from __future__ import annotations

import json

from app.core import http
from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus
from app.runtime import runtime


class SiemModule(Module):
    name = "siem"
    version = "0.1.0"
    description = "Connecteur SIEM/EDR (récupération de logs)"
    consumes = ["connectors"]

    def __init__(self, bus: EventBus, connectors) -> None:
        super().__init__(bus)
        self._conn = connectors

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    def _config(self) -> dict | None:
        raw = self._conn.get("siem")
        if not raw:
            return None
        try:
            cfg = json.loads(raw)
        except Exception:
            return None
        if not cfg.get("url"):
            return None
        return cfg

    def status(self) -> dict:
        cfg = self._config()
        return {
            "configured": cfg is not None,
            "airgapped": runtime.airgapped,
            "type": (cfg or {}).get("type", ""),
            "url": (cfg or {}).get("url", ""),
        }

    def _gate(self) -> dict | None:
        """Renvoie une erreur si l'appel ne peut pas se faire (air-gapped / non configuré)."""
        if runtime.airgapped:
            return {"ok": False, "reason": "mode air-gapped actif — désactive-le pour interroger le SIEM"}
        if self._config() is None:
            return {"ok": False, "reason": "connecteur SIEM non configuré (onglet Connecteurs)"}
        return None

    @staticmethod
    def _headers(cfg: dict) -> dict:
        token = cfg.get("token") or ""
        if not token:
            return {}
        return {"Authorization": (f"ApiKey {token}" if cfg.get("type") == "elastic" else f"Bearer {token}")}

    @staticmethod
    def build_search_url(cfg: dict) -> tuple[str, bool]:
        """Détermine l'URL et le mode (POST _search vs GET) selon le type/URL.

        Wazuh/Elastic → requête `_search` sur l'indexeur (les alertes Wazuh sont dans
        l'index wazuh-alerts-*). Générique → GET direct.
        """
        url = (cfg.get("url") or "").rstrip("/")
        typ = cfg.get("type", "generic")
        if url.endswith("_search"):
            return (url, True)
        if typ == "wazuh":
            return (f"{url}/wazuh-alerts-*/_search", True)
        if typ == "elastic":
            return (f"{url}/_search", True)
        return (url, False)

    def _fetch(self, cfg: dict, limit: int = 25):
        url, is_search = self.build_search_url(cfg)
        # Auth : basique (identifiants indexeur Wazuh) prioritaire, sinon token/ApiKey.
        auth = None
        if cfg.get("username") and cfg.get("password"):
            auth = (cfg["username"], cfg["password"])
        headers = self._headers(cfg)
        # Labs Wazuh : certificat auto-signé fréquent → vérif TLS désactivable (défaut False).
        # Cible souvent locale/LAN → local=True (on ignore un proxy système).
        verify = bool(cfg.get("verify", False))
        if is_search:
            body = {"size": limit, "sort": [{"@timestamp": {"order": "desc"}}], "query": {"match_all": {}}}
            return http.post(url, json=body, headers=headers, auth=auth, timeout=20, verify=verify, local=True)
        return http.get(url, headers=headers, auth=auth, timeout=20, verify=verify, local=True)

    def test(self) -> dict:
        blocked = self._gate()
        if blocked:
            return {"available": False, **blocked}
        cfg = self._config() or {}
        r = self._fetch(cfg, limit=1)
        if r.error:
            return {"available": True, "ok": False, "error": r.error}
        return {"available": True, "ok": r.ok, "status_code": r.status_code, "type": cfg.get("type", "")}

    def alerts(self, limit: int = 25) -> dict:
        blocked = self._gate()
        if blocked:
            return {"available": False, "alerts": [], **blocked}
        cfg = self._config() or {}
        r = self._fetch(cfg, limit=limit)
        if r.error:
            return {"available": True, "alerts": [], "error": r.error}
        if r.status_code >= 400:
            return {"available": True, "alerts": [], "error": f"HTTP {r.status_code} (auth/URL ?)"}
        data = r.json()
        if data is None:
            return {"available": True, "alerts": [], "error": "réponse non-JSON"}
        return {"available": True, "alerts": self._normalize(data, cfg.get("type", ""))[:limit]}

    @staticmethod
    def _normalize(data, kind: str) -> list[dict]:
        """Normalise la réponse en {time, level, rule, agent, description} — tolérant aux formats."""
        # Elastic : hits.hits[]._source ; Wazuh : data.affected_items[] ; générique : liste directe.
        items = data
        if isinstance(data, dict):
            if "hits" in data and isinstance(data["hits"], dict):
                items = [h.get("_source", h) for h in data["hits"].get("hits", [])]
            elif "data" in data and isinstance(data["data"], dict):
                items = data["data"].get("affected_items", [])
            elif "alerts" in data:
                items = data["alerts"]
            else:
                items = [data]
        out: list[dict] = []
        for it in items if isinstance(items, list) else []:
            if not isinstance(it, dict):
                continue
            rule = it.get("rule") if isinstance(it.get("rule"), dict) else {}
            out.append({
                "time": str(it.get("timestamp") or it.get("@timestamp") or it.get("time") or ""),
                "level": str(rule.get("level") or it.get("level") or it.get("severity") or ""),
                "rule": str(rule.get("description") or it.get("rule_description") or it.get("message") or it.get("description") or ""),
                "agent": str((it.get("agent") or {}).get("name") if isinstance(it.get("agent"), dict) else (it.get("agent") or it.get("host") or "")),
                "description": str(it.get("full_log") or it.get("description") or "")[:300],
            })
        return out
