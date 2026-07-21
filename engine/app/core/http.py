"""Appels réseau sortants — point de passage unique.

Tout appel HTTP externe (NVD, VirusTotal, AbuseIPDB, crt.sh, LLM, SIEM) transite
par ici. Bénéfices centralisés (à la manière de core.proc pour les commandes) :

 - **timeout systématique** (aucun appel ne peut bloquer le moteur) ;
 - **jamais d'exception qui traverse** : on renvoie un `Result` avec `.error`
   renseigné plutôt que de lever (l'appelant décide quoi afficher) ;
 - **En-tête User-Agent** cohérent ;
 - **`local=True`** : ignore les proxys d'environnement (`trust_env=False`) pour
   les cibles locales / de lab (Ollama sur 127.0.0.1, indexeur Wazuh du LAN) — évite
   qu'un VPN/proxy système intercepte une adresse locale.

⚠️ Le **gate air-gapped reste de la responsabilité de chaque module** (il porte un
message métier propre) : ce helper ne décide pas *s'il faut* appeler, seulement *comment*.
"""
from __future__ import annotations

import httpx

_UA = "RED-SHIELD/0.1 (+local security dashboard)"
DEFAULT_TIMEOUT = 25


class Result:
    """Enveloppe de réponse qui n'échoue jamais : `.ok`, `.status_code`, `.json()`, `.text`, `.error`."""

    __slots__ = ("_resp", "error")

    def __init__(self, resp: httpx.Response | None = None, error: str | None = None) -> None:
        self._resp = resp
        self.error = error

    @property
    def status_code(self) -> int:
        return self._resp.status_code if self._resp is not None else 0

    @property
    def ok(self) -> bool:
        return self._resp is not None and self._resp.status_code < 400

    @property
    def text(self) -> str:
        return self._resp.text if self._resp is not None else ""

    def json(self):
        if self._resp is None:
            return None
        try:
            return self._resp.json()
        except Exception:
            return None


def request(method: str, url: str, *, timeout: float = DEFAULT_TIMEOUT, local: bool = False,
            headers: dict | None = None, **kwargs) -> Result:
    hdr = {"User-Agent": _UA}
    if headers:
        hdr.update(headers)
    try:
        resp = httpx.request(method, url, timeout=timeout, headers=hdr,
                             trust_env=not local, **kwargs)
        return Result(resp=resp)
    except Exception as exc:
        return Result(error=str(exc))


def get(url: str, **kwargs) -> Result:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs) -> Result:
    return request("POST", url, **kwargs)
