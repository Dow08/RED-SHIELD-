"""Module LLM — analyse un rapport/scan par un LLM (clé fournie par l'utilisateur ou Ollama local).

Config stockée via le connecteur « llm » (JSON : provider, key, url, model). Gated par
air-gapped (sauf Ollama local qui reste hors-ligne). RED ne génère aucun compte ni clé.
"""
from __future__ import annotations

import json

from app.core import http
from app.core.bus import EventBus
from app.modules.base import Module, ModuleStatus
from app.runtime import runtime

_PROMPT = (
    "Tu es un analyste cybersécurité. Analyse ce {kind} et fournis, en français et de façon "
    "concise : (1) ce qui ne va pas, (2) le niveau de risque, (3) les étapes de remédiation "
    "priorisées.\n\n{text}"
)


class LlmModule(Module):
    name = "llm"
    version = "0.1.0"
    description = "Analyse IA (rapports/scan)"
    consumes = ["connectors"]

    def __init__(self, bus: EventBus, connectors) -> None:
        super().__init__(bus)
        self._conn = connectors

    def start(self) -> None:
        self.set_status(ModuleStatus.ACTIVE)

    def analyze(self, text: str, kind: str = "rapport") -> dict:
        cfg_raw = self._conn.get("llm")
        if not cfg_raw:
            return {"ok": False, "error": "connecteur LLM non configuré (onglet Connecteurs)"}
        try:
            cfg = json.loads(cfg_raw)
        except Exception:
            return {"ok": False, "error": "config LLM invalide"}
        provider = cfg.get("provider", "ollama")
        # Ollama local reste autorisé sous air-gapped ; les API distantes non.
        if runtime.airgapped and provider != "ollama":
            return {"ok": False, "error": "mode air-gapped actif — utilise Ollama local ou désactive air-gapped"}
        prompt = _PROMPT.format(kind=kind, text=text[:6000])
        try:
            if provider == "ollama":
                url = cfg.get("url", "http://localhost:11434").rstrip("/")
                # Ollama tourne en local → on ignore un éventuel proxy système (local=True).
                r = http.post(f"{url}/api/generate",
                              json={"model": cfg.get("model", "llama3"), "prompt": prompt, "stream": False},
                              timeout=180, local=True)
                if r.ok:
                    return {"ok": True, "analysis": (r.json() or {}).get("response", "")}
                return {"ok": False, "error": r.error or f"Ollama HTTP {r.status_code}"}
            if provider == "anthropic":
                r = http.post("https://api.anthropic.com/v1/messages",
                              headers={"x-api-key": cfg.get("key", ""), "anthropic-version": "2023-06-01", "content-type": "application/json"},
                              json={"model": cfg.get("model", "claude-sonnet-5"), "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]},
                              timeout=120)
                if r.ok:
                    return {"ok": True, "analysis": r.json()["content"][0]["text"]}
                return {"ok": False, "error": r.error or f"Anthropic HTTP {r.status_code}: {r.text[:200]}"}
            if provider == "openai":
                r = http.post("https://api.openai.com/v1/chat/completions",
                              headers={"Authorization": f"Bearer {cfg.get('key', '')}"},
                              json={"model": cfg.get("model", "gpt-4o-mini"), "messages": [{"role": "user", "content": prompt}]},
                              timeout=120)
                if r.ok:
                    return {"ok": True, "analysis": r.json()["choices"][0]["message"]["content"]}
                return {"ok": False, "error": r.error or f"OpenAI HTTP {r.status_code}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": False, "error": f"provider inconnu: {provider}"}
