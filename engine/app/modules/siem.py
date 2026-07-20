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

import httpx

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

    def test(self) -> dict:
        blocked = self._gate()
        if blocked:
            return {"available": False, **blocked}
        cfg = self._config() or {}
        try:
            r = httpx.get(cfg["url"], headers=self._headers(cfg), timeout=10, verify=cfg.get("verify", True))
            return {"available": True, "ok": r.status_code < 500, "status_code": r.status_code, "type": cfg.get("type", "")}
        except Exception as exc:
            return {"available": True, "ok": False, "error": str(exc)}

    @staticmethod
    def _headers(cfg: dict) -> dict:
        token = cfg.get("token") or ""
        if not token:
            return {}
        if cfg.get("type") == "elastic":
            return {"Authorization": f"ApiKey {token}"}
        return {"Authorization": f"Bearer {token}"}

    def alerts(self, limit: int = 25) -> dict:
        blocked = self._gate()
        if blocked:
            return {"available": False, "alerts": [], **blocked}
        cfg = self._config() or {}
        try:
            r = httpx.get(cfg["url"], headers=self._headers(cfg), timeout=15, verify=cfg.get("verify", True))
            if r.status_code >= 400:
                return {"available": True, "alerts": [], "error": f"HTTP {r.status_code}"}
            data = r.json()
        except Exception as exc:
            return {"available": True, "alerts": [], "error": str(exc)}
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
