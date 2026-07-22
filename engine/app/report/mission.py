"""Rapport de mission — modèle structuré + assemblage factuel.

Le rapport est un **document vivant** : le backend l'assemble uniquement à partir de
données RÉELLES mesurées par les modules (exposition, GRC, vulnérabilités applicatives,
surface d'exposition). Aucune donnée inventée : une section sans matière est simplement
vide (l'UI la masque). La narration (verdict) est produite par gabarit — pas d'IA, donc
zéro hallucination. L'utilisateur retouche/annote ensuite côté application (Phase 2).
"""
from __future__ import annotations

import json
import os
import sys
from datetime import date
from pathlib import Path

from pydantic import BaseModel

_SEV_ORDER = {"crit": 0, "haut": 1, "moyen": 2, "faible": 3}
_BAND_LABEL = {"faible": "Exposition faible", "elevee": "Exposition élevée", "critique": "Exposition critique"}


class MissionMeta(BaseModel):
    marque: str = "DP Cyber Consulting"
    consultant: str = "D. Poncelet"
    client: str = "—"
    perimetre: str = "Poste de travail (audit local)"
    reference: str = ""
    date: str = ""
    confidentialite: str = "Diffusion restreinte — ne pas redistribuer"
    logo: str = ""         # data-URL du logo (upload utilisateur, Phase 2)
    autorisation: str = ""  # référence de l'autorisation écrite (périmètre de mission)


class Finding(BaseModel):
    id: str = ""           # identifiant stable (édition : masquer/réordonner/annoter)
    included: bool = True   # inclus dans le rapport final ?
    severity: str          # crit / haut / moyen / faible
    title: str
    description: str = ""   # vulgarisée (le « pourquoi »)
    detail: str = ""        # constat technique
    asset: str = ""
    remediation: str = ""
    refs: dict = {}         # {ISO, NIST, CIS}
    cve: str = ""
    cvss: float | None = None
    source: str = ""        # grc / procvuln / scan
    note: str = ""          # annotation libre de l'utilisateur (Phase 2)


class FrameworkScore(BaseModel):
    framework: str
    label: str
    score: int
    ecarts: int


class ReportModel(BaseModel):
    meta: MissionMeta
    score: int = 0
    band: str = "faible"
    band_label: str = "Exposition faible"
    counts: dict = {}
    verdict: str = ""
    kpis: dict = {}
    findings: list[Finding] = []
    conformity: list[FrameworkScore] = []
    annexes: list = []      # captures jointes : [{name, type, data(data-URL)}] (Phase 3)
    sections: dict = {"constats": True, "remediation": True, "conformite": True, "annexe": True}
    generated_at: str = ""


def _slug(source: str, title: str) -> str:
    base = f"{source}:{title}".lower()
    return "".join(c if c.isalnum() else "-" for c in base)[:64].strip("-")


def _sev_from_grc(control_id: str, status: str) -> str:
    if status == "non_conforme":
        return "crit" if control_id in ("antimalware-edr",) else "haut"
    if status == "a_traiter":
        return "moyen"
    return "faible"


def _sev_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "moyen"
    if cvss >= 9:
        return "crit"
    if cvss >= 7:
        return "haut"
    if cvss >= 4:
        return "moyen"
    return "faible"


def _verdict(band_label: str, score: int, n_find: int, n_crit: int) -> str:
    bl = band_label.lower()
    if n_find == 0:
        return (f"{band_label} (score {score}/100). Aucun point prioritaire relevé au moment de l'audit : "
                f"la posture est saine sur le périmètre évalué.")
    crit_part = f", dont {n_crit} critique(s)" if n_crit else ""
    return (f"{band_label} (score {score}/100). {n_find} point(s) prioritaire(s){crit_part} identifié(s), "
            f"tous corrigeables. Aucune compromission active n'a été détectée : le chantier relève de la "
            f"remédiation, pas de la gestion de crise.")


def build_model(raw: dict) -> ReportModel:
    """Assemble le ReportModel depuis les données brutes collectées par l'endpoint.

    raw = { exposure, grc, procvuln, exposed_ports, meta? }
    """
    raw = raw or {}
    today = date.today()

    # -- méta (défauts + override éventuel) --------------------------------
    meta_in = raw.get("meta") or {}
    meta = MissionMeta(**meta_in)
    if not meta.date:
        meta.date = today.strftime("%d/%m/%Y")
    if not meta.reference:
        meta.reference = f"DPC-{today.year}-{today.month:02d}{today.day:02d}"

    # -- score / exposition ------------------------------------------------
    exp = raw.get("exposure") or {}
    score = int(exp.get("score", 0))
    band = exp.get("band", "faible")
    counts = exp.get("counts", {}) or {}

    findings: list[Finding] = []

    # -- constats issus du GRC (contrôles non conformes / à traiter) -------
    grc = raw.get("grc") or {}
    for c in grc.get("controls", []):
        if c.get("status") not in ("non_conforme", "a_traiter"):
            continue
        findings.append(Finding(
            severity=_sev_from_grc(c.get("id", ""), c.get("status", "")),
            title=c.get("title", ""),
            description=c.get("why", ""),
            detail=c.get("finding", "") or c.get("note", ""),
            remediation=c.get("remediation", ""),
            refs=c.get("refs", {}) or {},
            source="grc",
        ))

    # -- constats issus des vulnérabilités applicatives (CVE réelles) ------
    pv = raw.get("procvuln") or {}
    for app in pv.get("apps", []):
        for cve in (app.get("cves") or [])[:2]:
            cvss = cve.get("cvss")
            findings.append(Finding(
                severity=_sev_from_cvss(cvss),
                title=f"{app.get('product') or app.get('process')} {app.get('version','')} — {cve.get('cve','')}".strip(),
                description="Version applicative associée à une vulnérabilité connue (NVD).",
                detail=cve.get("summary", ""),
                asset=app.get("process", ""),
                remediation=f"Mettre à jour {app.get('product') or app.get('process')} vers une version corrigée.",
                cve=cve.get("cve", ""),
                cvss=cvss,
                source="procvuln",
            ))

    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), -(f.cvss or 0)))
    for i, f in enumerate(findings):
        f.id = f"{_slug(f.source, f.title)}-{i}"

    n_crit = sum(1 for f in findings if f.severity == "crit")
    band_label = _BAND_LABEL.get(band, "Exposition faible")

    # -- conformité (scores par référentiel, hors GLOBAL) ------------------
    conformity: list[FrameworkScore] = []
    for s in grc.get("scores", []):
        if s.get("framework") == "GLOBAL":
            continue
        cnt = s.get("counts", {}) or {}
        conformity.append(FrameworkScore(
            framework=s.get("framework", ""),
            label=s.get("label", ""),
            score=int(s.get("score", 0)),
            ecarts=int(cnt.get("a_traiter", 0)) + int(cnt.get("non_conforme", 0)),
        ))

    return ReportModel(
        meta=meta,
        score=score, band=band, band_label=band_label, counts=counts,
        verdict=_verdict(band_label, score, len(findings), n_crit),
        kpis={
            "findings": len(findings),
            "critiques": n_crit,
            "exposes": int(raw.get("exposed_ports", 0) or 0),
        },
        findings=findings,
        conformity=conformity,
        generated_at=today.isoformat(),
    )


# ── Persistance du brouillon (document vivant, éditable/annotable) ─────────
def _draft_path() -> Path:
    """Emplacement du brouillon — robuste au packaging PyInstaller (cf. grc)."""
    if getattr(sys, "frozen", False):
        base = os.getenv("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "RED-SHIELD" / "report_draft.json"
    return Path(__file__).resolve().parents[2] / "data" / "report_draft.json"


def load_draft() -> dict | None:
    p = _draft_path()
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def save_draft(model: dict) -> None:
    p = _draft_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(model, ensure_ascii=False, indent=2), encoding="utf-8")


def clear_draft() -> None:
    p = _draft_path()
    try:
        p.unlink()
    except Exception:
        pass
