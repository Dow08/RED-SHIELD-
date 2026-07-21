"""Recherche de CVE **en ligne** via l'API NVD (National Vulnerability Database).

Remplace toute base locale : les CVE sont interrogées directement chez NVD (source
officielle, à jour). Partagé par le scan nmap et l'inventaire des applications.

- Gated par le mode **air-gapped** (aucun appel externe si actif → renvoie « désactivé »).
- Cache en mémoire (produit+version) + throttle (NVD limite ~5 req/30 s sans clé ;
  clé optionnelle via la variable d'env `NVD_API_KEY` → 50 req/30 s).
- 100 % factuel : uniquement ce que renvoie NVD, jamais inventé.
"""
from __future__ import annotations

import os
import threading
import time

from app.core import http
from app.runtime import runtime

_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cache: dict[str, list[dict]] = {}
_cache_lock = threading.Lock()
_rate_lock = threading.Lock()
_last_call = [0.0]


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return ""


def _cvss(cve: dict) -> tuple[float, str]:
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            m = arr[0]
            data = m.get("cvssData", {}) or {}
            score = float(data.get("baseScore", 0.0) or 0.0)
            sev = (m.get("baseSeverity") or data.get("baseSeverity") or _severity_from_score(score) or "").lower()
            return (score, sev)
    return (0.0, "")


def parse_nvd(data: dict, limit: int = 10) -> list[dict]:
    """Normalise la réponse NVD en liste {cve, cvss, severity, summary, url}."""
    out: list[dict] = []
    for item in data.get("vulnerabilities", []) or []:
        c = item.get("cve", {}) or {}
        cid = c.get("id", "")
        if not cid:
            continue
        summary = ""
        for d in c.get("descriptions", []) or []:
            if d.get("lang") == "en":
                summary = d.get("value", "")
                break
        score, sev = _cvss(c)
        out.append({"cve": cid, "cvss": score, "severity": sev,
                    "summary": summary[:220], "url": f"https://nvd.nist.gov/vuln/detail/{cid}"})
    out.sort(key=lambda x: x["cvss"], reverse=True)
    return out[:limit]


def lookup(product: str, version: str = "") -> dict:
    """CVE d'un produit (+version optionnelle) via NVD. Renvoie {available, reason?, cves}."""
    if runtime.airgapped:
        return {"available": False, "reason": "air-gapped actif — désactive-le pour interroger NVD", "cves": []}
    product = (product or "").strip()
    if not product:
        return {"available": True, "cves": []}
    key = f"{product.lower()}|{(version or '').strip()}"
    with _cache_lock:
        if key in _cache:
            return {"available": True, "cves": _cache[key]}
    api_key = os.getenv("NVD_API_KEY", "").strip()
    with _rate_lock:  # throttle : ~1 req/6 s sans clé (respecte la limite NVD)
        wait = (0.7 if api_key else 6.0) - (time.monotonic() - _last_call[0])
        if wait > 0:
            time.sleep(wait)
        _last_call[0] = time.monotonic()
    q = f"{product} {version}".strip()
    headers = {"apiKey": api_key} if api_key else {}
    r = http.get(_NVD, params={"keywordSearch": q, "resultsPerPage": 20}, headers=headers)
    if r.error:
        return {"available": True, "reason": r.error, "cves": []}
    if r.status_code != 200:
        return {"available": True, "reason": f"NVD HTTP {r.status_code}", "cves": []}
    cves = parse_nvd(r.json() or {})
    with _cache_lock:
        _cache[key] = cves
    return {"available": True, "cves": cves, "source": "NVD (keyword)"}
